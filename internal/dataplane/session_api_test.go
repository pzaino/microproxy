package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pzaino/microproxy/pkg/config"
)

func testSessionAPIConfig(addr string) *config.Config {
	return &config.Config{
		SchemaVersion: "1",
		Listeners: []config.ListenerConfig{
			{Name: "edge-http-sticky", Type: "http", Address: "127.0.0.1:0", Enabled: true, Provider: "sticky"},
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
		},
		SessionControl: config.SessionControlConfig{
			Enabled:     true,
			Address:     addr,
			BearerToken: "secret-token-123",
			Provider:    "sticky",
		},
	}
}

func startSessionAPI(t *testing.T, cfg *config.Config, manager *SessionManager) (*SessionAPIServer, string) {
	t.Helper()
	return startSessionAPIWithCallback(t, cfg, manager, nil)
}

func startSessionAPIWithCallback(t *testing.T, cfg *config.Config, manager *SessionManager, onRotate func()) (*SessionAPIServer, string) {
	t.Helper()
	server := NewSessionAPIServer(cfg, manager, onRotate)
	if server == nil {
		t.Fatal("expected session api server")
	}
	// Bind to ephemeral port for tests.
	server.server.Addr = "127.0.0.1:0"
	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("start session api: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return server, "http://" + server.Addr()
}

func TestSessionAPI_RotateSuccess(t *testing.T) {
	t.Parallel()
	cfg := testSessionAPIConfig("127.0.0.1:0")
	manager, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	var callbacks atomic.Int32
	_, base := startSessionAPIWithCallback(t, cfg, manager, func() { callbacks.Add(1) })

	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/sessions/rotate", nil)
	req.Header.Set("Authorization", "Bearer secret-token-123")
	req.Header.Set("Idempotency-Key", "job-rotate-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rotate request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["status"] != "rotated" || payload["provider"] != "sticky" {
		t.Fatalf("unexpected payload %+v", payload)
	}
	if gen, ok := payload["generation"].(float64); !ok || gen != 2 {
		t.Fatalf("expected generation 2, got %+v", payload)
	}
	if _, ok := payload["replayed"]; ok {
		t.Fatalf("new rotation must not carry replayed flag: %+v", payload)
	}
	for key := range payload {
		switch key {
		case "status", "provider", "generation":
		default:
			t.Fatalf("rotation response must not expose %q: %+v", key, payload)
		}
	}
	if got := callbacks.Load(); got != 1 {
		t.Fatalf("expected exactly one rotation callback, got %d", got)
	}
}

func TestSessionAPI_IdempotentReplay(t *testing.T) {
	t.Parallel()
	cfg := testSessionAPIConfig("127.0.0.1:0")
	manager, _ := NewSessionManager(cfg)
	var callbacks atomic.Int32
	_, base := startSessionAPIWithCallback(t, cfg, manager, func() { callbacks.Add(1) })

	doRotate := func(key string) (float64, bool, map[string]any) {
		req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/sessions/rotate", nil)
		req.Header.Set("Authorization", "Bearer secret-token-123")
		req.Header.Set("Idempotency-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("rotate: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("rotate %q: expected 200, got %d: %s", key, resp.StatusCode, string(body))
		}
		var payload map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		gen, _ := payload["generation"].(float64)
		replayed, _ := payload["replayed"].(bool)
		return gen, replayed, payload
	}
	first, firstReplayed, firstPayload := doRotate("replay-key")
	if firstReplayed {
		t.Fatalf("first rotation must not be a replay: %+v", firstPayload)
	}
	before, _ := manager.Snapshot("sticky")
	second, secondReplayed, secondPayload := doRotate("replay-key")
	if !secondReplayed {
		t.Fatalf("latest-key replay must set replayed=true: %+v", secondPayload)
	}
	if first != second {
		t.Fatalf("replay must return same generation %v vs %v", first, second)
	}
	after, _ := manager.Snapshot("sticky")
	if before != after {
		t.Fatalf("replay must not create a new identity: %+v vs %+v", before, after)
	}
	if got := callbacks.Load(); got != 1 {
		t.Fatalf("replay must not run rotation callback again, got %d", got)
	}
	third, _, _ := doRotate("replay-key-2")
	if third == first {
		t.Fatal("unique key must advance generation")
	}
	if got := callbacks.Load(); got != 2 {
		t.Fatalf("expected callback for each new rotation, got %d", got)
	}
}

func TestSessionAPI_StaleKeyConflict(t *testing.T) {
	t.Parallel()
	cfg := testSessionAPIConfig("127.0.0.1:0")
	manager, _ := NewSessionManager(cfg)
	var callbacks atomic.Int32
	_, base := startSessionAPIWithCallback(t, cfg, manager, func() { callbacks.Add(1) })

	rotate := func(key string) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/sessions/rotate", nil)
		req.Header.Set("Authorization", "Bearer secret-token-123")
		req.Header.Set("Idempotency-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("rotate %q: %v", key, err)
		}
		defer resp.Body.Close()
		var payload map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		return resp.StatusCode, payload
	}

	if status, _ := rotate("job-old"); status != http.StatusOK {
		t.Fatalf("first rotation: %d", status)
	}
	first, _ := manager.Snapshot("sticky")
	if status, _ := rotate("job-new"); status != http.StatusOK {
		t.Fatalf("second rotation: %d", status)
	}
	second, _ := manager.Snapshot("sticky")
	status, payload := rotate("job-old")
	if status != http.StatusConflict {
		t.Fatalf("expected 409 for stale key, got %d: %+v", status, payload)
	}
	errObj, _ := payload["error"].(map[string]any)
	if errObj["code"] != "stale_idempotency_key" {
		t.Fatalf("unexpected error payload %+v", payload)
	}
	if payload["provider"] != "sticky" {
		t.Fatalf("expected provider in response, got %+v", payload)
	}
	if original, _ := payload["original_generation"].(float64); uint64(original) != first.Generation {
		t.Fatalf("expected original generation %d, got %+v", first.Generation, payload)
	}
	if current, _ := payload["current_generation"].(float64); uint64(current) != second.Generation {
		t.Fatalf("expected current generation %d, got %+v", second.Generation, payload)
	}
	after, _ := manager.Snapshot("sticky")
	if after != second {
		t.Fatalf("stale key must not mutate identity: %+v vs %+v", second, after)
	}
	if got := callbacks.Load(); got != 2 {
		t.Fatalf("stale key must not run rotation callback, got %d", got)
	}
}

func TestSessionAPI_AuthFailures(t *testing.T) {
	t.Parallel()
	cfg := testSessionAPIConfig("127.0.0.1:0")
	manager, _ := NewSessionManager(cfg)
	_, base := startSessionAPI(t, cfg, manager)

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"wrong", "Bearer wrong-token", http.StatusUnauthorized},
		{"missing-scheme", "secret-token-123", http.StatusUnauthorized},
		{"empty-bearer", "Bearer", http.StatusUnauthorized},
		{"empty-bearer-spaces", "Bearer   ", http.StatusUnauthorized},
		{"extra-fields", "Bearer secret-token-123 extra", http.StatusUnauthorized},
		{"basic-scheme", "Basic secret-token-123", http.StatusUnauthorized},
		{"lowercase-scheme", "bearer secret-token-123", http.StatusOK},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/sessions/rotate", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		req.Header.Set("Idempotency-Key", "k-"+tc.name)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("%s: expected %d, got %d", tc.name, tc.want, resp.StatusCode)
		}
	}

	// X-API-Key alone must fail.
	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/sessions/rotate", nil)
	req.Header.Set("X-API-Key", "secret-token-123")
	req.Header.Set("Idempotency-Key", "k-xapi-only")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("x-api-key only: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for X-API-Key alone, got %d", resp.StatusCode)
	}

	// Duplicate Authorization headers are malformed, even if one is valid.
	req, _ = http.NewRequest(http.MethodPost, base+"/api/v1/sessions/rotate", nil)
	req.Header["Authorization"] = []string{"Bearer secret-token-123", "Bearer wrong-token"}
	req.Header.Set("Idempotency-Key", "k-duplicate-auth")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("duplicate auth: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for duplicate Authorization headers, got %d", resp.StatusCode)
	}
}

func TestSessionAPI_NoneAuthLoopbackAllowsUnauthenticated(t *testing.T) {
	t.Parallel()
	cfg := testSessionAPIConfig("127.0.0.1:0")
	cfg.SessionControl.AuthType = config.SessionControlAuthNone
	cfg.SessionControl.BearerToken = ""
	manager, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	_, base := startSessionAPI(t, cfg, manager)

	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/sessions/rotate", nil)
	req.Header.Set("Idempotency-Key", "none-auth-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 without credentials in none mode, got %d: %s", resp.StatusCode, string(body))
	}

	req, _ = http.NewRequest(http.MethodGet, base+"/api/v1/sessions/status", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected unauthenticated status in none mode, got %d", resp.StatusCode)
	}
}

func TestSessionAPI_NoneAuthNonLoopbackRequiresExplicitOptIn(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{"0.0.0.0:0", ":0", "192.0.2.1:0"} {
		addr := addr
		t.Run(addr, func(t *testing.T) {
			t.Parallel()
			cfg := testSessionAPIConfig(addr)
			cfg.SessionControl.AuthType = config.SessionControlAuthNone
			cfg.SessionControl.BearerToken = ""
			manager, _ := NewSessionManager(cfg)
			server := NewSessionAPIServer(cfg, manager, nil)
			if server == nil {
				t.Fatal("expected server")
			}
			if err := server.Start(context.Background()); err == nil {
				_ = server.Shutdown(context.Background())
				t.Fatalf("expected non-loopback none-auth start to fail for %q", addr)
			} else if !strings.Contains(err.Error(), "loopback") {
				t.Fatalf("expected loopback error for %q, got %v", addr, err)
			}
		})
	}
}

func TestSessionAPI_NoneAuthNonLoopbackOptInStarts(t *testing.T) {
	t.Parallel()
	cfg := testSessionAPIConfig("0.0.0.0:0")
	cfg.SessionControl.AuthType = config.SessionControlAuthNone
	cfg.SessionControl.BearerToken = ""
	cfg.SessionControl.AllowUnauthenticatedNonLoopback = true
	manager, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	server := NewSessionAPIServer(cfg, manager, nil)
	if server == nil {
		t.Fatal("expected server")
	}
	if err := server.Start(context.Background()); err != nil {
		t.Fatalf("explicit opt-in must allow non-loopback start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	_, port, err := net.SplitHostPort(server.Addr())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+port+"/api/v1/sessions/status", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected unauthenticated status with opt-in, got %d", resp.StatusCode)
	}
}

func TestSessionAPI_BearerModeRequiresTokenAtStart(t *testing.T) {
	t.Parallel()
	cfg := testSessionAPIConfig("127.0.0.1:0")
	cfg.SessionControl.BearerToken = ""
	manager, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	server := NewSessionAPIServer(cfg, manager, nil)
	if server == nil {
		t.Fatal("expected server")
	}
	if err := server.Start(context.Background()); err == nil {
		_ = server.Shutdown(context.Background())
		t.Fatal("expected empty bearer token start failure")
	}
}

func TestSessionAPI_MethodAndKeyValidation(t *testing.T) {
	t.Parallel()
	cfg := testSessionAPIConfig("127.0.0.1:0")
	manager, _ := NewSessionManager(cfg)
	_, base := startSessionAPI(t, cfg, manager)

	req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/sessions/rotate", nil)
	req.Header.Set("Authorization", "Bearer secret-token-123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get rotate: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, base+"/api/v1/sessions/rotate", nil)
	req.Header.Set("Authorization", "Bearer secret-token-123")
	// Missing key.
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("missing key: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing key, got %d", resp.StatusCode)
	}
}

func TestSessionAPI_OversizedBodyRejected(t *testing.T) {
	t.Parallel()
	cfg := testSessionAPIConfig("127.0.0.1:0")
	manager, _ := NewSessionManager(cfg)
	_, base := startSessionAPI(t, cfg, manager)

	big := strings.Repeat("x", 8*1024)
	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/sessions/rotate", strings.NewReader(big))
	req.Header.Set("Authorization", "Bearer secret-token-123")
	req.Header.Set("Idempotency-Key", "big-body-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("big body: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", resp.StatusCode)
	}
}

func TestSessionAPI_RNGFailure503PreservesGeneration(t *testing.T) {
	t.Parallel()
	cfg := testSessionAPIConfig("127.0.0.1:0")
	calls := 0
	randFn := func(n int) ([]byte, error) {
		calls++
		if calls == 1 {
			b := make([]byte, n)
			for i := range b {
				b[i] = 0xAB
			}
			return b, nil
		}
		return nil, errors.New("rng failure")
	}
	manager, err := NewSessionManagerWithRand(cfg, randFn, time.Now)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	var callbacks atomic.Int32
	_, base := startSessionAPIWithCallback(t, cfg, manager, func() { callbacks.Add(1) })
	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/sessions/rotate", nil)
	req.Header.Set("Authorization", "Bearer secret-token-123")
	req.Header.Set("Idempotency-Key", "rng-fail-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
	if gen, _ := manager.Generation("sticky"); gen != 1 {
		t.Fatalf("generation must stay 1 after RNG failure, got %d", gen)
	}
	if got := callbacks.Load(); got != 0 {
		t.Fatalf("failed rotation must not run connection cleanup callback, got %d", got)
	}
}

func TestSessionAPI_StatusEndpoint(t *testing.T) {
	t.Parallel()
	cfg := testSessionAPIConfig("127.0.0.1:0")
	manager, _ := NewSessionManager(cfg)
	_, base := startSessionAPI(t, cfg, manager)

	req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/sessions/status", nil)
	req.Header.Set("Authorization", "Bearer secret-token-123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["provider"] != "sticky" || payload["generation"] != float64(1) {
		t.Fatalf("unexpected status %+v", payload)
	}
	// Status must not expose session id.
	raw, _ := json.Marshal(payload)
	if strings.Contains(string(raw), "session_id") {
		t.Fatal("status must not expose session identity")
	}
}

func TestSessionAPI_PortCollisionFailsStart(t *testing.T) {
	t.Parallel()
	// Occupy a port with a dummy listener, then try to start API on same port.
	dummy := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {}))
	defer dummy.Close()
	// Extract port and reuse address for collision.
	addr := strings.TrimPrefix(dummy.URL, "http://")
	cfg := testSessionAPIConfig(addr)
	manager, _ := NewSessionManager(cfg)
	server := NewSessionAPIServer(cfg, manager, nil)
	if server == nil {
		t.Fatal("expected server")
	}
	if err := server.Start(context.Background()); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		t.Fatal("expected port collision error")
	}
}
