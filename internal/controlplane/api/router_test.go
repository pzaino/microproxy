package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pzaino/microproxy/pkg/config"
)

func withDefaultAuth(req *http.Request) {
	req.Header.Set(apiKeyHeader, defaultControlAPIKey)
}

func newTestRouter(t *testing.T, cfg *config.Config) http.Handler {
	t.Helper()
	t.Setenv(controlPlaneAPIKeysEnv, defaultControlAPIKey)
	t.Setenv(controlPlaneJWTsEnv, "")
	t.Setenv(developmentModeEnv, "false")
	return NewRouter(cfg)
}

func TestHealthEndpoint(t *testing.T) {
	h := newTestRouter(t, config.NewConfig())
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
	cfg.Providers = []config.ProviderConfig{
		{
			Name: "test-provider",
			Auth: config.ProviderAuthConfig{
				Type:     "api_key",
				Password: "very-secret-password",
				Token:    "very-secret-token",
				Headers: map[string]string{
					"Authorization": "Bearer very-secret-authz",
					"X-Api-Key":     "very-secret-api-key",
					"X-Trace":       "not-secret",
				},
			},
		},
	}
	h := newTestRouter(t, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	withDefaultAuth(req)
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

	payload := rw.Body.String()
	for _, secret := range []string{
		"very-secret-password",
		"very-secret-token",
		"very-secret-authz",
		"very-secret-api-key",
	} {
		if strings.Contains(payload, secret) {
			t.Fatalf("expected secret %q to be redacted from payload", secret)
		}
	}
	if !strings.Contains(payload, redactedSecretValue) {
		t.Fatalf("expected payload to include redaction marker")
	}
	if !strings.Contains(payload, "not-secret") {
		t.Fatalf("expected non-sensitive headers to remain visible")
	}
}

func TestProviderItemEndpointStub(t *testing.T) {
	h := newTestRouter(t, config.NewConfig())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/providers/demo", nil)
	withDefaultAuth(req)
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

func TestAPIRouteUnauthorized(t *testing.T) {
	h := newTestRouter(t, config.NewConfig())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	rw := httptest.NewRecorder()

	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 got %d", rw.Code)
	}
	var body ErrorEnvelope
	if err := json.Unmarshal(rw.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Error.Code != "unauthorized" {
		t.Fatalf("expected unauthorized code, got %q", body.Error.Code)
	}
}

func TestAPIRouteForbidden(t *testing.T) {
	h := newTestRouter(t, config.NewConfig())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	req.Header.Set(apiKeyHeader, "wrong-key")
	rw := httptest.NewRecorder()

	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusForbidden {
		t.Fatalf("expected 403 got %d", rw.Code)
	}
	var body ErrorEnvelope
	if err := json.Unmarshal(rw.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Error.Code != "forbidden" {
		t.Fatalf("expected forbidden code, got %q", body.Error.Code)
	}
}

func TestAPIRouteAuthorized(t *testing.T) {
	h := newTestRouter(t, config.NewConfig())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	withDefaultAuth(req)
	rw := httptest.NewRecorder()

	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rw.Code)
	}
}

func TestNewRouterWithErrorWithoutCredentials(t *testing.T) {
	t.Setenv(controlPlaneAPIKeysEnv, "")
	t.Setenv(controlPlaneJWTsEnv, "")
	t.Setenv(developmentModeEnv, "false")

	_, err := NewRouterWithError(config.NewConfig())
	if err == nil {
		t.Fatalf("expected configuration error")
	}
	if !strings.Contains(err.Error(), controlPlaneAPIKeysEnv) {
		t.Fatalf("expected error to reference %s, got %v", controlPlaneAPIKeysEnv, err)
	}
}

func TestNewRouterWithErrorDevelopmentModeAllowsDefaultKey(t *testing.T) {
	t.Setenv(controlPlaneAPIKeysEnv, "")
	t.Setenv(controlPlaneJWTsEnv, "")
	t.Setenv(developmentModeEnv, "true")

	h, err := NewRouterWithError(config.NewConfig())
	if err != nil {
		t.Fatalf("expected development mode to allow default key, got %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	req.Header.Set(apiKeyHeader, defaultControlAPIKey)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rw.Code)
	}
}
