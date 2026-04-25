package policy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/pkg/config"
)

const (
	ActionAllow         = "allow"
	ActionDeny          = "deny"
	ActionRouteOverride = "route_override"
	ActionHeadersPatch  = "headers_patch"
)

// Engine evaluates policies referenced by resolved route decisions.
type Engine struct {
	policies map[string]config.PolicyConfig
}

func NewEngine(cfg *config.Config) *Engine {
	engine := &Engine{policies: map[string]config.PolicyConfig{}}
	if cfg == nil {
		return engine
	}
	for _, policy := range cfg.Policies {
		name := strings.TrimSpace(policy.Name)
		if name == "" {
			continue
		}
		engine.policies[name] = policy
	}
	return engine
}

func (e *Engine) Evaluate(req *http.Request, metadata listeners.RequestMetadata, route listeners.RouteDecision) listeners.PolicyDecision {
	decision := listeners.PolicyDecision{Action: ActionAllow}
	policyRef := strings.TrimSpace(route.Policy)
	if e == nil || policyRef == "" {
		return decision
	}

	policy, ok := e.policies[policyRef]
	if !ok {
		return listeners.PolicyDecision{PolicyName: policyRef, Action: ActionAllow}
	}
	if !matches(policy.Selectors, req, metadata, route) {
		return listeners.PolicyDecision{PolicyName: policy.Name, Action: ActionAllow}
	}

	action := strings.ToLower(strings.TrimSpace(policy.Action))
	result := listeners.PolicyDecision{PolicyName: policy.Name, Action: action}
	switch action {
	case ActionDeny:
		result.DenyCode = valueOrDefault(policy.Parameters["reason_code"], "policy_denied")
		result.DenyMessage = valueOrDefault(policy.Parameters["reason"], "request denied by policy")
	case ActionRouteOverride:
		result.RouteOverride = strings.TrimSpace(policy.Parameters["provider"])
		if result.RouteOverride == "" {
			result.Action = ActionAllow
		}
	case ActionHeadersPatch:
		result.HeadersPatch = extractSafeHeaders(policy.Parameters)
		if len(result.HeadersPatch) == 0 {
			result.Action = ActionAllow
		}
	case ActionAllow:
		// no-op
	default:
		result.Action = ActionAllow
	}
	return result
}

func matches(selectors map[string]string, req *http.Request, metadata listeners.RequestMetadata, route listeners.RouteDecision) bool {
	if len(selectors) == 0 {
		return true
	}
	for key, value := range selectors {
		want := strings.TrimSpace(value)
		switch normalized := strings.ToLower(strings.TrimSpace(key)); {
		case normalized == "tenant" || normalized == "tenant_id":
			if metadata.TenantID != want {
				return false
			}
		case normalized == "provider":
			if route.Provider != want {
				return false
			}
		case normalized == "method":
			if !strings.EqualFold(req.Method, want) {
				return false
			}
		case normalized == "host":
			if !strings.EqualFold(requestHost(req.URL), want) {
				return false
			}
		case normalized == "path_prefix":
			if !strings.HasPrefix(req.URL.Path, want) {
				return false
			}
		case strings.HasPrefix(normalized, "header:"):
			headerName := strings.TrimSpace(key[len("header:"):])
			if req.Header.Get(headerName) != want {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func extractSafeHeaders(parameters map[string]string) map[string]string {
	patched := map[string]string{}
	for key, value := range parameters {
		headerName := strings.TrimSpace(key)
		if strings.EqualFold(headerName, "reason") || strings.EqualFold(headerName, "reason_code") || strings.EqualFold(headerName, "provider") {
			continue
		}
		if !isSafePatchHeader(headerName) {
			continue
		}
		patched[http.CanonicalHeaderKey(headerName)] = value
	}
	return patched
}

func isSafePatchHeader(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	if strings.HasPrefix(lower, "x-") {
		return true
	}
	switch lower {
	case "traceparent", "tracestate", "baggage":
		return true
	default:
		return false
	}
}

func requestHost(target *url.URL) string {
	if target == nil {
		return ""
	}
	return target.Hostname()
}

func valueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
