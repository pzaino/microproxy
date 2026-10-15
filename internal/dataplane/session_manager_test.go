package dataplane

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pzaino/microproxy/pkg/config"
)

func stickyTestConfig() *config.Config {
	return &config.Config{
		SchemaVersion: "1",
		Listeners: []config.ListenerConfig{
			{Name: "edge-http", Type: "http", Address: "127.0.0.1:0", Enabled: true, Provider: "sticky"},
		},
		Providers: []config.ProviderConfig{
			{
				Name:      "sticky",
				Type:      "http_proxy",
				Auth:      config.ProviderAuthConfig{Type: "basic", Username: "base-user", Password: "base-pass"},
				Endpoints: []config.ProviderEndpoint{{URL: "http://upstream.example:3128"}},
				Session: config.ProviderSessionConfig{
					Supported:        true,
					Mode:             "username_template",
					UsernameTemplate: "{{username}}-session-{{session_id}}",
				},
			},
			{
				Name:      "static",
				Type:      "http_proxy",
				Auth:      config.ProviderAuthConfig{Type: "basic", Username: "s-user", Password: "s-pass"},
				Endpoints: []config.ProviderEndpoint{{URL: "http://upstream.example:3128"}},
			},
		},
	}
}

func TestSessionManager_InitialGeneration(t *testing.T) {
	t.Parallel()
	m, err := NewSessionManager(stickyTestConfig())
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	snapshot, ok := m.Snapshot("sticky")
	if !ok {
		t.Fatal("expected sticky snapshot")
	}
	if snapshot.Generation != 1 {
		t.Fatalf("expected generation 1, got %d", snapshot.Generation)
	}
	if len(snapshot.SessionID) != 32 {
		t.Fatalf("expected 32-char hex session id, got %q", snapshot.SessionID)
	}
	for _, r := range snapshot.SessionID {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("expected lowercase hex, got %q", snapshot.SessionID)
		}
	}
	if _, ok := m.Snapshot("static"); ok {
		t.Fatal("static provider must not have a session identity")
	}
	if _, ok := m.Snapshot("missing"); ok {
		t.Fatal("unknown provider must not have a session identity")
	}
}

func TestSessionManager_RotateChangesIdentity(t *testing.T) {
	t.Parallel()
	m, err := NewSessionManager(stickyTestConfig())
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	before, _ := m.Snapshot("sticky")
	after, replayed, err := m.Rotate("sticky", "job-1")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if replayed {
		t.Fatal("first use of key must not be a replay")
	}
	if after.Generation != 2 {
		t.Fatalf("expected generation 2, got %d", after.Generation)
	}
	if after.SessionID == before.SessionID {
		t.Fatal("expected session id to change after rotation")
	}
	current, _ := m.Snapshot("sticky")
	if current.SessionID != after.SessionID || current.Generation != 2 {
		t.Fatalf("snapshot must reflect committed rotation, got %+v", current)
	}
}

func TestSessionManager_Idempotency(t *testing.T) {
	t.Parallel()
	m, err := NewSessionManager(stickyTestConfig())
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	first, _, err := m.Rotate("sticky", "job-boundary-1")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	second, replayed, err := m.Rotate("sticky", "job-boundary-1")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !replayed {
		t.Fatal("expected replay flag for duplicate key")
	}
	if second.Generation != first.Generation || second.SessionID != first.SessionID {
		t.Fatalf("replay must return prior generation %+v vs %+v", first, second)
	}
	third, _, err := m.Rotate("sticky", "job-boundary-2")
	if err != nil {
		t.Fatalf("rotate 2: %v", err)
	}
	if third.Generation != first.Generation+1 {
		t.Fatalf("unique key must advance generation, got %d want %d", third.Generation, first.Generation+1)
	}
}

func TestSessionManager_InvalidKeys(t *testing.T) {
	t.Parallel()
	m, err := NewSessionManager(stickyTestConfig())
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	for _, key := range []string{"", "   ", strings.Repeat("a", 257), "has space", "bad\x01char", "bad*char"} {
		if _, _, err := m.Rotate("sticky", key); err == nil {
			t.Fatalf("expected invalid key %q to fail", key)
		}
	}
}

func TestSessionManager_RNGFailurePreservesState(t *testing.T) {
	t.Parallel()
	calls := 0
	randFn := func(n int) ([]byte, error) {
		calls++
		if calls == 1 {
			b := make([]byte, n)
			for i := range b {
				b[i] = byte(i + 1)
			}
			return b, nil
		}
		return nil, errors.New("rng exploded")
	}
	m, err := NewSessionManagerWithRand(stickyTestConfig(), randFn, time.Now)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	before, _ := m.Snapshot("sticky")
	if _, _, err := m.Rotate("sticky", "job-fail"); err == nil {
		t.Fatal("expected RNG failure")
	}
	after, _ := m.Snapshot("sticky")
	if after != before {
		t.Fatalf("failure must preserve previous state %+v vs %+v", before, after)
	}
}

func TestSessionManager_ConcurrentRotateRaceSafe(t *testing.T) {
	t.Parallel()
	m, err := NewSessionManager(stickyTestConfig())
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	const workers = 32
	var wg sync.WaitGroup
	results := make([]uint64, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			snapshot, _, err := m.Rotate("sticky", fmt.Sprintf("concurrent-key-%d", idx))
			if err == nil {
				results[idx] = snapshot.Generation
			}
			errs[idx] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	seen := map[uint64]bool{}
	for _, gen := range results {
		if seen[gen] {
			t.Fatalf("duplicate generation %d across unique keys", gen)
		}
		seen[gen] = true
	}
	final, _ := m.Snapshot("sticky")
	if final.Generation != 1+workers {
		t.Fatalf("expected generation %d, got %d", 1+workers, final.Generation)
	}
}

func TestSessionManager_ConcurrentSnapshotAndRotate(t *testing.T) {
	t.Parallel()
	m, err := NewSessionManager(stickyTestConfig())
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = m.Snapshot("sticky")
				if idx == 0 {
					_, _, _ = m.Rotate("sticky", fmt.Sprintf("k-%d", j))
				}
			}
		}(i)
	}
	wg.Wait()
}
