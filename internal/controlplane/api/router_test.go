package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pzaino/microproxy/pkg/config"
)

func TestHealthEndpoint(t *testing.T) {
	h := NewRouter(config.NewConfig())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rw := httptest.NewRecorder()

	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rw.Code)
	}
	if rw.Header().Get(requestIDHeader) == "" {
		t.Fatalf("expected request id header")
	}

	var body HealthResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Status != "ok" {
		t.Fatalf("unexpected status: %s", body.Status)
	}
}

func TestConfigEndpoint(t *testing.T) {
	cfg := config.NewConfig()
	cfg.SchemaVersion = "test-version"
	h := NewRouter(cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	rw := httptest.NewRecorder()

	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rw.Code)
	}

	var body ConfigResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	content, ok := body.Config.(map[string]any)
	if !ok {
		t.Fatalf("expected map config payload")
	}
	if content["schema_version"] != "test-version" {
		t.Fatalf("expected schema_version=test-version, got %v", content["schema_version"])
	}
}

func TestProviderItemEndpointStub(t *testing.T) {
	h := NewRouter(config.NewConfig())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/providers/demo", nil)
	rw := httptest.NewRecorder()

	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 got %d", rw.Code)
	}

	var body ErrorEnvelope
	if err := json.Unmarshal(rw.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Error.Code != "not_implemented" {
		t.Fatalf("unexpected error code: %s", body.Error.Code)
	}
	if body.Error.RequestID == "" {
		t.Fatalf("expected request id in error envelope")
	}
}
