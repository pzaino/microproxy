package observability

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pzaino/microproxy/pkg/config"
)

func TestSharedObservabilityHTTPRoutes(t *testing.T) {
	const addr = "127.0.0.1:9090"
	cfg := &config.Config{
		SchemaVersion: "1",
		Listeners: []config.ListenerConfig{
			{Name: "edge", Type: "http", Address: "127.0.0.1:8080", Enabled: true},
		},
		Observability: config.ObservabilityConfig{
			Metrics: config.MetricsConfig{Enabled: true, Address: addr},
			HealthEndpoints: config.HealthEndpointsConfig{
				LivenessAddress: addr, ReadinessAddress: addr, StartupAddress: addr,
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("shared observability configuration should validate: %v", err)
	}
	manager, ok := NewListenerManager(cfg).(*HTTPListenerManager)
	if !ok {
		t.Fatal("expected concrete observability listener manager")
	}
	if len(manager.servers) != 1 {
		t.Fatalf("expected one shared observability server, got %d", len(manager.servers))
	}
	for _, path := range []string{"/metrics", "/healthz", "/readyz", "/startupz"} {
		rec := httptest.NewRecorder()
		manager.servers[0].server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: expected HTTP 200, got %d", path, rec.Code)
		}
	}
}
