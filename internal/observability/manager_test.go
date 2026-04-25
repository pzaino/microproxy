package observability

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/pkg/config"
)

func TestNewListenerManager_FallbackToNoop(t *testing.T) {
	t.Parallel()

	mgr := NewListenerManager(nil)
	if _, ok := mgr.(NoopListenerManager); !ok {
		t.Fatalf("expected NoopListenerManager, got %T", mgr)
	}

	mgr = NewListenerManager(&config.Config{})
	if _, ok := mgr.(NoopListenerManager); !ok {
		t.Fatalf("expected NoopListenerManager for empty observability config, got %T", mgr)
	}
}

func TestNewListenerManager_ConcreteAndLifecycle(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.Observability.HealthEndpoints.LivenessAddress = "127.0.0.1:0"
	cfg.Observability.Metrics.Enabled = true
	cfg.Observability.Metrics.Address = "127.0.0.1:0"

	mgr := NewListenerManager(cfg)
	httpMgr, ok := mgr.(*HTTPListenerManager)
	if !ok {
		t.Fatalf("expected *HTTPListenerManager, got %T", mgr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := httpMgr.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if err := httpMgr.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestHTTPMiddleware_AddsRequestIDHeader(t *testing.T) {
	t.Parallel()

	handler := HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		metadata, ok := listeners.MetadataFromContext(req.Context())
		if !ok {
			t.Fatalf("expected request metadata in context")
		}
		if metadata.RequestID == "" {
			t.Fatalf("expected non-empty request id")
		}
		rw.WriteHeader(http.StatusCreated)
	}), true)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/hello", nil)
	req = req.WithContext(listeners.WithMetadata(req.Context(), listeners.RequestMetadata{RequestID: "req-test", Provider: "provider-a", TenantID: "tenant-a"}))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if got := rr.Result().Header.Get("X-Request-ID"); got != "req-test" {
		t.Fatalf("expected X-Request-ID=req-test, got %q", got)
	}
}

func TestMetricsStore_EmitsPolicyLabelsAndCounters(t *testing.T) {
	t.Parallel()

	store := newMetricsStore()
	store.observe(http.MethodGet, http.StatusForbidden, "provider-a", "tenant-a", "deny", "blocked_scope", 10*time.Millisecond)

	rr := httptest.NewRecorder()
	store.handlePrometheus(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, err := io.ReadAll(rr.Result().Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, `policy_action="deny"`) {
		t.Fatalf("expected policy action label in metrics, got: %s", text)
	}
	if !strings.Contains(text, "microproxy_policy_decisions_total") {
		t.Fatalf("expected policy decisions metric in output")
	}
}
