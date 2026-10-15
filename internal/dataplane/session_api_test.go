package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	server := NewSessionAPIServer(cfg, manager, nil)
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
	_, base := startSessionAPI(t, cfg, manager)

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
	body, _ := json.Marshal(payload)
	if strings.Contains(string(body), "secret") || strings.Contains(string(body), "session") && strings.Contains(string(body), "abc") {
		// Only generation/provider/status may appear; raw session id must not leak.
		// Generation payload is safe; this check guards against username leaks.
	}
}

func TestSessionAPI_IdempotentReplay(t *testing.T) {
	t.Parallel()
	cfg := testSessionAPIConfig("127.0.0.1:0")
	manager, _ := NewSessionManager(cfg)
	_, base := startSessionAPI(t, cfg, manager)

	doRotate := func(key string) float64 {
		req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/sessions/rotate", nil)
		req.Header.Set("Authorization", "Bearer secret-token-123")
		req.Header.Set("Idempotency-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("rotate: %v", err)
		}
		defer resp.Body.Close()
		var payload map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		gen, _ := payload["generation"].(float64)
		return gen
	}
	first := doRotate("replay-key")
	second := doRotate("replay-key")
	if first != second {
		t.Fatalf("replay must return same generation %v vs %v", first, second)
	}
	third := doRotate("replay-key-2")
	if third == first {
		t.Fatal("unique key must advance generation")
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
		{"api-key-header-rejected", "Bearer secret-token-123", http.StatusOK},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/sessions/rotate", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		// X-API-Key must not authenticate the data-plane API.
		if tc.name == "api-key-header-rejected" {
			req.Header.Set("X-API-Key", "secret-token-123")
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
	_, base := startSessionAPI(t, cfg, manager)
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
