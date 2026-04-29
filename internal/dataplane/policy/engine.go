package policy

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/pkg/config"
)

const (
	ActionAllow                = "allow"
	ActionDeny                 = "deny"
	ActionRouteOverride        = "route_override"
	ActionHeadersPatch         = "headers_patch"
	ActionRedirect             = "redirect"
	ActionRewrite              = "rewrite"
	ActionResponseHeadersPatch = "response_headers_patch"
	ActionBodyMutationHook     = "body_mutation_hook"
)

type compiledPolicy struct {
	config.PolicyConfig
	urlRegex          *regexp.Regexp
	domainSuffixRegex *regexp.Regexp
	contentTypeRegex  *regexp.Regexp
}

// Engine evaluates policies referenced by resolved route decisions.
type Engine struct {
	policies               map[string]compiledPolicy
	defaultChainMode       string
	allowRequestHeaderMute bool
	allowResponseHeaderMut bool
	allowRedirectRewrite   bool
	allowBodyMutations     bool
}

func NewEngine(cfg *config.Config) *Engine {
	engine := &Engine{
		policies:         map[string]compiledPolicy{},
		defaultChainMode: "stop",
	}
	if cfg == nil {
		return engine
	}
	if mode := strings.ToLower(strings.TrimSpace(cfg.PolicyEngine.ChainMode)); mode == "continue" {
		engine.defaultChainMode = mode
	}
	engine.allowRequestHeaderMute = cfg.PolicyEngine.SafeMode.AllowRequestHeaderMutation
	engine.allowResponseHeaderMut = cfg.PolicyEngine.SafeMode.AllowResponseHeaderMutation
	engine.allowRedirectRewrite = cfg.PolicyEngine.SafeMode.AllowRedirectRewrite
	engine.allowBodyMutations = cfg.PolicyEngine.SafeMode.AllowBodyMutation

	for _, policy := range cfg.Policies {
		name := strings.TrimSpace(policy.Name)
		if name == "" {
			continue
		}
		engine.policies[name] = compilePolicy(policy)
	}
	return engine
}

func (e *Engine) Evaluate(req *http.Request, metadata listeners.RequestMetadata, route listeners.RouteDecision) listeners.PolicyDecision {
	decision := listeners.PolicyDecision{Action: ActionAllow}
	if e == nil {
		return decision
	}

	policyRefs := parsePolicyRefs(route.Policy)
	if len(policyRefs) == 0 {
		return decision
	}

	trace := make([]string, 0, len(policyRefs))
	result := listeners.PolicyDecision{Action: ActionAllow}
	for _, ref := range policyRefs {
		policy, ok := e.policies[ref]
		if !ok {
			trace = append(trace, ref+":missing")
			continue
		}
		if !matches(policy, req, metadata, route) {
			trace = append(trace, policy.Name+":skip")
			continue
		}
		current, suppression := applyAction(policy.PolicyConfig, e.allowRequestHeaderMute, e.allowResponseHeaderMut, e.allowRedirectRewrite, e.allowBodyMutations)
		current.PolicyName = policy.Name
		if suppression != "" {
			trace = append(trace, policy.Name+":suppressed:"+suppression)
		} else {
			trace = append(trace, policy.Name+":"+current.Action)
		}
		result = mergeDecisions(result, current)
		if shouldStop(e.defaultChainMode, policy.Parameters, current.Action) {
			break
		}
	}
	result.Trace = trace
	if result.PolicyName == "" && len(policyRefs) > 0 {
		result.PolicyName = policyRefs[0]
	}
	return result
}

func parsePolicyRefs(policyRef string) []string {
	parts := strings.Split(policyRef, ",")
	refs := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			refs = append(refs, trimmed)
		}
	}
	return refs
}

func shouldStop(defaultMode string, parameters map[string]string, action string) bool {
	mode := strings.ToLower(strings.TrimSpace(parameters["chain_mode"]))
	if mode == "" {
		mode = defaultMode
	}
	if action == ActionDeny || action == ActionRedirect {
		return true
	}
	return mode != "continue"
}

func mergeDecisions(base, current listeners.PolicyDecision) listeners.PolicyDecision {
	if current.Action != "" && current.Action != ActionAllow {
		base.Action = current.Action
	}
	base.PolicyName = current.PolicyName
	base.DenyCode = valueOrDefault(current.DenyCode, base.DenyCode)
	base.DenyMessage = valueOrDefault(current.DenyMessage, base.DenyMessage)
	base.DenyCategory = valueOrDefault(current.DenyCategory, base.DenyCategory)
	base.RouteOverride = valueOrDefault(current.RouteOverride, base.RouteOverride)
	base.RedirectURL = valueOrDefault(current.RedirectURL, base.RedirectURL)
	base.RewriteScheme = valueOrDefault(current.RewriteScheme, base.RewriteScheme)
	base.RewriteHost = valueOrDefault(current.RewriteHost, base.RewriteHost)
	base.RewritePathPrefix = valueOrDefault(current.RewritePathPrefix, base.RewritePathPrefix)
	base.RequestBodyPrefix = valueOrDefault(current.RequestBodyPrefix, base.RequestBodyPrefix)
	base.ResponseBodyPrefix = valueOrDefault(current.ResponseBodyPrefix, base.ResponseBodyPrefix)
	base.HeadersPatch = mergeMap(base.HeadersPatch, current.HeadersPatch)
	base.ResponseHeadersPatch = mergeMap(base.ResponseHeadersPatch, current.ResponseHeadersPatch)
	return base
}

func mergeMap(base, current map[string]string) map[string]string {
	if len(current) == 0 {
		return base
	}
	if base == nil {
		base = map[string]string{}
	}
	for k, v := range current {
		base[k] = v
	}
	return base
}

func compilePolicy(policy config.PolicyConfig) compiledPolicy {
	compiled := compiledPolicy{PolicyConfig: policy}
	if expr := strings.TrimSpace(policy.Selectors["url_regex"]); expr != "" {
		compiled.urlRegex, _ = regexp.Compile(expr)
	}
	if expr := strings.TrimSpace(policy.Selectors["domain_suffix_regex"]); expr != "" {
		compiled.domainSuffixRegex, _ = regexp.Compile(expr)
	}
	if expr := strings.TrimSpace(policy.Selectors["content_type_regex"]); expr != "" {
		compiled.contentTypeRegex, _ = regexp.Compile(expr)
	}
	return compiled
}

func applyAction(policy config.PolicyConfig, allowRequestHeaderMutation, allowResponseHeaderMutation, allowRedirectRewrite, allowBodyMutations bool) (listeners.PolicyDecision, string) {
	action := strings.ToLower(strings.TrimSpace(policy.Action))
	result := listeners.PolicyDecision{Action: action}
	suppressionReason := ""
	switch action {
	case ActionDeny:
		result.DenyCode = valueOrDefault(policy.Parameters["reason_code"], "policy_denied")
		result.DenyMessage = valueOrDefault(policy.Parameters["reason"], "request denied by policy")
		result.DenyCategory = valueOrDefault(policy.Parameters["deny_category"], "other")
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
		if !allowRequestHeaderMutation {
			result.Action = ActionAllow
			result.HeadersPatch = nil
			suppressionReason = "request_header_mutation_guardrail"
		}
	case ActionResponseHeadersPatch:
		result.ResponseHeadersPatch = extractSafeHeaders(policy.Parameters)
		if len(result.ResponseHeadersPatch) == 0 {
			result.Action = ActionAllow
		}
		if !allowResponseHeaderMutation {
			result.Action = ActionAllow
			result.ResponseHeadersPatch = nil
			suppressionReason = "response_header_mutation_guardrail"
		}
	case ActionRedirect:
		result.RedirectURL = strings.TrimSpace(policy.Parameters["location"])
		if result.RedirectURL == "" {
			result.Action = ActionAllow
		}
		if !allowRedirectRewrite {
			result.Action = ActionAllow
			result.RedirectURL = ""
			suppressionReason = "redirect_rewrite_guardrail"
		}
	case ActionRewrite:
		result.RewriteScheme = strings.TrimSpace(policy.Parameters["scheme"])
		result.RewriteHost = strings.TrimSpace(policy.Parameters["host"])
		result.RewritePathPrefix = strings.TrimSpace(policy.Parameters["path_prefix"])
		if result.RewriteScheme == "" && result.RewriteHost == "" && result.RewritePathPrefix == "" {
			result.Action = ActionAllow
		}
		if !allowRedirectRewrite {
			result.Action = ActionAllow
			result.RewriteScheme = ""
			result.RewriteHost = ""
			result.RewritePathPrefix = ""
			suppressionReason = "redirect_rewrite_guardrail"
		}
	case ActionBodyMutationHook:
		if !allowBodyMutations {
			result.Action = ActionAllow
			suppressionReason = "body_mutation_guardrail"
			return result, suppressionReason
		}
		result.RequestBodyPrefix = policy.Parameters["request_prefix"]
		result.ResponseBodyPrefix = policy.Parameters["response_prefix"]
		if result.RequestBodyPrefix == "" && result.ResponseBodyPrefix == "" {
			result.Action = ActionAllow
		}
	case ActionAllow:
	default:
		result.Action = ActionAllow
	}
	return result, suppressionReason
}

func matches(policy compiledPolicy, req *http.Request, metadata listeners.RequestMetadata, route listeners.RouteDecision) bool {
	if len(policy.Selectors) == 0 {
		return true
	}
	for key, value := range policy.Selectors {
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
			if req != nil && !strings.EqualFold(req.Method, want) {
				return false
			}
		case normalized == "host":
			if req == nil || !strings.EqualFold(requestHost(req.URL), want) {
				return false
			}
		case normalized == "path_prefix":
			if req == nil || !strings.HasPrefix(req.URL.Path, want) {
				return false
			}
		case normalized == "url_regex":
			rawURL := ""
			if req != nil && req.URL != nil {
				rawURL = req.URL.String()
			}
			if policy.urlRegex == nil || !policy.urlRegex.MatchString(rawURL) {
				return false
			}
		case normalized == "domain_suffix_regex":
			host := ""
			if req != nil && req.URL != nil {
				host = requestHost(req.URL)
			}
			if policy.domainSuffixRegex == nil || !policy.domainSuffixRegex.MatchString(host) {
				return false
			}
		case normalized == "content_type_regex":
			contentType := valueOrDefault(metadata.ContentType, headerValue(req, "Content-Type"))
			if policy.contentTypeRegex == nil || !policy.contentTypeRegex.MatchString(contentType) {
				return false
			}
		case normalized == "request_size_min":
			if !compareSize(metadata.RequestSize, want, true) {
				return false
			}
		case normalized == "request_size_max":
			if !compareSize(metadata.RequestSize, want, false) {
				return false
			}
		case normalized == "response_size_min":
			if !compareSize(metadata.ResponseSize, want, true) {
				return false
			}
		case normalized == "response_size_max":
			if !compareSize(metadata.ResponseSize, want, false) {
				return false
			}
		case normalized == "time_window_utc":
			now := metadata.EvaluationClock
			if now.IsZero() {
				now = time.Now().UTC()
			}
			if !withinWindow(want, now) {
				return false
			}
		case strings.HasPrefix(normalized, "header:"):
			headerName := strings.TrimSpace(key[len("header:"):])
			if headerValue(req, headerName) != want {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func headerValue(req *http.Request, key string) string {
	if req == nil {
		return ""
	}
	return req.Header.Get(key)
}

func compareSize(actual int64, expectedRaw string, min bool) bool {
	expected, err := strconv.ParseInt(strings.TrimSpace(expectedRaw), 10, 64)
	if err != nil {
		return false
	}
	if actual < 0 {
		return false
	}
	if min {
		return actual >= expected
	}
	return actual <= expected
}

func withinWindow(window string, now time.Time) bool {
	parts := strings.Split(window, "-")
	if len(parts) != 2 {
		return false
	}
	start, err := time.Parse("15:04", strings.TrimSpace(parts[0]))
	if err != nil {
		return false
	}
	end, err := time.Parse("15:04", strings.TrimSpace(parts[1]))
	if err != nil {
		return false
	}
	currentMinute := now.UTC().Hour()*60 + now.UTC().Minute()
	startMinute := start.Hour()*60 + start.Minute()
	endMinute := end.Hour()*60 + end.Minute()
	if startMinute <= endMinute {
		return currentMinute >= startMinute && currentMinute <= endMinute
	}
	return currentMinute >= startMinute || currentMinute <= endMinute
}

func extractSafeHeaders(parameters map[string]string) map[string]string {
	patched := map[string]string{}
	for key, value := range parameters {
		headerName := strings.TrimSpace(key)
		switch strings.ToLower(headerName) {
		case "reason", "reason_code", "provider", "location", "scheme", "host", "path_prefix", "request_prefix", "response_prefix", "deny_category", "chain_mode":
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
