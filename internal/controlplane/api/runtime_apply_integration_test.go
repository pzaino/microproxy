package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pzaino/microproxy/pkg/config"
)

func TestRuntimeApplyLiveStateChangesAndRollback(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Routing.DefaultProvider = "p1"
	cfg.Providers = []config.ProviderConfig{{Name: "p1", Type: "http", Endpoints: []config.ProviderEndpoint{{URL: "https://one.example"}}}}
	h := NewHandlers(cfg)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/providers/p1", strings.NewReader(`{"resourceVersion":"1","patch":{"endpoint":"https://two.example"}}`))
	req.SetPathValue("providerID", "p1")
	rw := httptest.NewRecorder()
	h.PatchProvider(rw, req)
	if rw.Code != http.StatusOK { t.Fatalf("expected 200 got %d", rw.Code) }
	provider, _ := h.registry.Get("p1")
	if provider.Endpoints[0].URL.String() != "https://two.example" { t.Fatalf("expected runtime registry endpoint update") }

	h.cfg.Observability.AccessLog.Format = "force-runtime-fail"
	failReq := httptest.NewRequest(http.MethodPatch, "/api/v1/providers/p1", strings.NewReader(`{"resourceVersion":"2","patch":{"endpoint":"https://three.example"}}`))
	failReq.SetPathValue("providerID", "p1")
	failRW := httptest.NewRecorder()
	h.PatchProvider(failRW, failReq)
	if failRW.Code != http.StatusInternalServerError { t.Fatalf("expected 500 got %d", failRW.Code) }
	provider, _ = h.registry.Get("p1")
	if provider.Endpoints[0].URL.String() != "https://two.example" { t.Fatalf("rollback failed; got %s", provider.Endpoints[0].URL.String()) }
}
