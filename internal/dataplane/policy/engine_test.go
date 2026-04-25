package policy

import (
	"net/http/httptest"
	"testing"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/pkg/config"
)

func TestEngineEvaluate_DenyAndMatchers(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Policies: []config.PolicyConfig{{
		Name:   "deny-admin",
		Action: "deny",
		Selectors: map[string]string{
			"tenant":         "tenant-a",
			"method":         "GET",
			"host":           "example.com",
			"path_prefix":    "/admin",
			"header:X-Scope": "blocked",
		},
		Parameters: map[string]string{"reason_code": "blocked_scope", "reason": "admin endpoint blocked"},
	}}}
	engine := NewEngine(cfg)

	req := httptest.NewRequest("GET", "http://example.com/admin/panel", nil)
	req.Header.Set("X-Scope", "blocked")

	decision := engine.Evaluate(req, listeners.RequestMetadata{TenantID: "tenant-a"}, listeners.RouteDecision{Provider: "p1", Policy: "deny-admin"})
	if decision.Action != ActionDeny {
		t.Fatalf("expected %q action, got %q", ActionDeny, decision.Action)
	}
	if decision.DenyCode != "blocked_scope" {
		t.Fatalf("unexpected deny code %q", decision.DenyCode)
	}
}

func TestEngineEvaluate_RouteOverrideAndHeadersPatch(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Policies: []config.PolicyConfig{
		{Name: "override", Action: "route_override", Parameters: map[string]string{"provider": "provider-b"}},
		{Name: "patch", Action: "headers_patch", Parameters: map[string]string{"X-Trace-ID": "trace-1", "Authorization": "nope", "traceparent": "00-abc"}},
	}}
	engine := NewEngine(cfg)
	req := httptest.NewRequest("POST", "http://svc.local/v1", nil)

	overrideDecision := engine.Evaluate(req, listeners.RequestMetadata{}, listeners.RouteDecision{Policy: "override"})
	if overrideDecision.Action != ActionRouteOverride || overrideDecision.RouteOverride != "provider-b" {
		t.Fatalf("unexpected override decision: %+v", overrideDecision)
	}

	patchDecision := engine.Evaluate(req, listeners.RequestMetadata{}, listeners.RouteDecision{Policy: "patch"})
	if patchDecision.Action != ActionHeadersPatch {
		t.Fatalf("expected headers_patch action, got %q", patchDecision.Action)
	}
	if _, ok := patchDecision.HeadersPatch["Authorization"]; ok {
		t.Fatalf("unsafe header should not be patched")
	}
	if patchDecision.HeadersPatch["X-Trace-Id"] != "trace-1" {
		t.Fatalf("expected X-Trace-ID patch, got %+v", patchDecision.HeadersPatch)
	}
}
