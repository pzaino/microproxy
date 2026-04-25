package policy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
		Parameters: map[string]string{"reason_code": "blocked_scope", "reason": "admin endpoint blocked", "deny_category": "security"},
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
	if decision.DenyCategory != "security" {
		t.Fatalf("unexpected deny category %q", decision.DenyCategory)
	}
}

func TestEngineEvaluate_AdditionalActionsAndSelectors(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		PolicyEngine: config.PolicyEngineConfig{ChainMode: "continue"},
		Policies: []config.PolicyConfig{
			{Name: "override", Action: "route_override", Parameters: map[string]string{"provider": "provider-b", "chain_mode": "continue"}},
			{Name: "patch", Action: "headers_patch", Parameters: map[string]string{"X-Trace-ID": "trace-1", "Authorization": "nope", "traceparent": "00-abc"}, Selectors: map[string]string{"url_regex": "^http://svc\\.local/v1"}},
			{Name: "rewrite", Action: "rewrite", Parameters: map[string]string{"host": "rewritten.local"}},
			{Name: "response-patch", Action: "response_headers_patch", Parameters: map[string]string{"X-Response-Policy": "enabled"}},
			{Name: "redirect", Action: "redirect", Parameters: map[string]string{"location": "https://docs.example.com/blocked"}, Selectors: map[string]string{"content_type_regex": "^application/json"}},
		}}
	engine := NewEngine(cfg)
	req := httptest.NewRequest("POST", "http://svc.local/v1", nil)
	req.Header.Set("Content-Type", "application/json")

	overrideDecision := engine.Evaluate(req, listeners.RequestMetadata{}, listeners.RouteDecision{Policy: "override,patch,rewrite,response-patch"})
	if overrideDecision.RouteOverride != "provider-b" {
		t.Fatalf("unexpected override decision: %+v", overrideDecision)
	}
	if overrideDecision.HeadersPatch["X-Trace-Id"] != "trace-1" {
		t.Fatalf("expected headers patch from chained policy, got %+v", overrideDecision.HeadersPatch)
	}
	if _, ok := overrideDecision.HeadersPatch["Authorization"]; ok {
		t.Fatalf("unsafe header should not be patched")
	}
	if overrideDecision.ResponseHeadersPatch["X-Response-Policy"] != "enabled" {
		t.Fatalf("expected response header patch, got %+v", overrideDecision.ResponseHeadersPatch)
	}

	redirectDecision := engine.Evaluate(req, listeners.RequestMetadata{ContentType: "application/json"}, listeners.RouteDecision{Policy: "redirect"})
	if redirectDecision.Action != ActionRedirect || redirectDecision.RedirectURL == "" {
		t.Fatalf("expected redirect decision, got %+v", redirectDecision)
	}
}

func TestEngineEvaluate_SizeAndTimeSelectors(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Policies: []config.PolicyConfig{{
		Name:   "windowed",
		Action: ActionDeny,
		Selectors: map[string]string{
			"request_size_min": "10",
			"request_size_max": "100",
			"time_window_utc":  "00:00-23:59",
		},
	}}}
	engine := NewEngine(cfg)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	decision := engine.Evaluate(req, listeners.RequestMetadata{
		RequestSize:     55,
		EvaluationClock: time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC),
	}, listeners.RouteDecision{Policy: "windowed"})
	if decision.Action != ActionDeny {
		t.Fatalf("expected deny action, got %q", decision.Action)
	}
}
