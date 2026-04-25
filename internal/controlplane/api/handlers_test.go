package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pzaino/microproxy/pkg/config"
)

type testTimeoutError struct{ msg string }

func (t testTimeoutError) Error() string   { return t.msg }
func (t testTimeoutError) Timeout() bool   { return true }
func (t testTimeoutError) Temporary() bool { return true }

func TestCreateProviderHandlerSuccess(t *testing.T) {
	h := NewHandlers(config.NewConfig())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/providers", strings.NewReader(`{"provider":{"id":"p1","name":"Provider 1","type":"http","endpoint":"https://example.test"}}`))
	rw := httptest.NewRecorder()

	h.CreateProvider(rw, req)

	if rw.Code != http.StatusCreated {
		t.Fatalf("expected 201 got %d", rw.Code)
	}
	var resp ProviderResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Provider.ResourceVersion != "1" {
		t.Fatalf("expected version 1 got %q", resp.Provider.ResourceVersion)
	}
}

func TestReplaceProviderHandlerConflict(t *testing.T) {
	h := NewHandlers(config.NewConfig())
	seed := httptest.NewRequest(http.MethodPost, "/api/v1/providers", strings.NewReader(`{"provider":{"id":"p1","name":"Provider 1","type":"http","endpoint":"https://example.test"}}`))
	h.CreateProvider(httptest.NewRecorder(), seed)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/providers/p1", strings.NewReader(`{"resourceVersion":"999","provider":{"name":"Provider 1","type":"http","endpoint":"https://example.test"}}`))
	req.SetPathValue("providerID", "p1")
	rw := httptest.NewRecorder()

	h.ReplaceProvider(rw, req)

	if rw.Code != http.StatusConflict {
		t.Fatalf("expected 409 got %d", rw.Code)
	}
}

func TestPatchProviderHandlerValidationFailure(t *testing.T) {
	h := NewHandlers(config.NewConfig())
	seed := httptest.NewRequest(http.MethodPost, "/api/v1/providers", strings.NewReader(`{"provider":{"id":"p1","name":"Provider 1","type":"http","endpoint":"https://example.test"}}`))
	h.CreateProvider(httptest.NewRecorder(), seed)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/providers/p1", strings.NewReader(`{"resourceVersion":"1","patch":{"name":""}}`))
	req.SetPathValue("providerID", "p1")
	rw := httptest.NewRecorder()

	h.PatchProvider(rw, req)

	if rw.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 got %d", rw.Code)
	}
}

func TestDeleteProviderHandlerSuccess(t *testing.T) {
	h := NewHandlers(config.NewConfig())
	seed := httptest.NewRequest(http.MethodPost, "/api/v1/providers", strings.NewReader(`{"provider":{"id":"p1","name":"Provider 1","type":"http","endpoint":"https://example.test"}}`))
	h.CreateProvider(httptest.NewRecorder(), seed)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/providers/p1?resourceVersion=1", nil)
	req.SetPathValue("providerID", "p1")
	rw := httptest.NewRecorder()

	h.DeleteProvider(rw, req)

	if rw.Code != http.StatusNoContent {
		t.Fatalf("expected 204 got %d", rw.Code)
	}
}

func TestListProvidersIncludesRuntimeHealth(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.ProviderConfig{{
			Name:      "p1",
			Type:      "http",
			Endpoints: []config.ProviderEndpoint{{URL: "http://p1-primary.example", Priority: 1}},
			Health:    config.ProviderHealthConfig{Enabled: true, IntervalSeconds: 1, TimeoutSeconds: 1, FailureThreshold: 1},
		}},
	}
	h := NewHandlers(cfg)
	provider, _ := h.registry.Get("p1")
	h.registry.ObserveEndpointOutcome("p1", provider.Endpoints[0].URL, testTimeoutError{msg: "connect timeout"}, "connect_timeout")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/providers", nil)
	rw := httptest.NewRecorder()
	h.ListProviders(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rw.Code)
	}
	var response ProviderListResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(response.Items) != 1 {
		t.Fatalf("expected 1 provider item, got %d", len(response.Items))
	}
	if got := response.Items[0].Health.State; got != "open" {
		t.Fatalf("expected provider health state open, got %q", got)
	}
	if got := response.Items[0].Health.Endpoints[0].Reason; got == "" {
		t.Fatalf("expected endpoint health reason to be populated")
	}
}
