package dataplane

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/pkg/config"
)

// RouteDecision captures the selected tenant/provider for a request.
type RouteDecision struct {
	TenantID string
	Provider string
	Policy   string
}

// RuntimeProvider is the runtime representation of an upstream provider.
type RuntimeProvider struct {
	Name      string
	Endpoints []RuntimeEndpoint
}

// RuntimeEndpoint is a single dialable upstream endpoint.
type RuntimeEndpoint struct {
	URL      *url.URL
	Priority int
	Weight   int
	Adapter  listeners.UpstreamAdapter
}

// TimeoutClassification identifies whether an error was timeout-related.
type TimeoutClassification string

const (
	TimeoutUnknown   TimeoutClassification = "unknown"
	TimeoutTransient TimeoutClassification = "transient"
	TimeoutDeadline  TimeoutClassification = "deadline_exceeded"
	TimeoutConnect   TimeoutClassification = "connect_timeout"
)

func NewRequestRuntime(cfg *config.Config) listeners.RequestRuntime {
	registry := NewProviderRegistry(cfg)
	return listeners.RequestRuntime{
		Resolver:          NewRouteResolver(cfg),
		Registry:          registry,
		Selector:          NewEndpointSelector(),
		ClassifyTimeoutFn: ClassifyTimeout,
	}
}

// RouteResolver resolves tenant/provider from metadata and routing rules.
type RouteResolver struct {
	defaultProvider string
	rules           []config.RoutingRule
}

func NewRouteResolver(cfg *config.Config) *RouteResolver {
	if cfg == nil {
		return &RouteResolver{}
	}
	return &RouteResolver{defaultProvider: strings.TrimSpace(cfg.Routing.DefaultProvider), rules: append([]config.RoutingRule{}, cfg.Routing.Rules...)}
}

func (r *RouteResolver) Resolve(_ *http.Request, metadata listeners.RequestMetadata) (listeners.RouteDecision, error) {
	decision := listeners.RouteDecision{TenantID: metadata.TenantID}
	if provider := strings.TrimSpace(metadata.Provider); provider != "" {
		decision.Provider = provider
		return decision, nil
	}

	for _, rule := range r.rules {
		if matchesRule(rule.Match, metadata) {
			decision.Provider = rule.Provider
			decision.Policy = rule.PolicyRef
			if decision.Provider != "" {
				return decision, nil
			}
		}
	}

	decision.Provider = r.defaultProvider
	if decision.Provider == "" {
		return decision, nil
	}
	return decision, nil
}

func matchesRule(match map[string]string, metadata listeners.RequestMetadata) bool {
	if len(match) == 0 {
		return false
	}
	for key, value := range match {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "tenant", "tenant_id", "tenantid":
			if metadata.TenantID != value {
				return false
			}
		case "provider", "provider_id", "providerid":
			if metadata.Provider != value {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ProviderRegistry stores providers keyed by provider name.
type ProviderRegistry struct {
	providers map[string]RuntimeProvider
}

func NewProviderRegistry(cfg *config.Config) *ProviderRegistry {
	registry := &ProviderRegistry{providers: map[string]RuntimeProvider{}}
	if cfg == nil {
		return registry
	}
	adapterFactory := upstreamAdapterFactory{}

	for _, provider := range cfg.Providers {
		runtimeProvider := RuntimeProvider{Name: provider.Name}
		adapter := adapterFactory.ForProvider(provider)
		for _, endpoint := range provider.Endpoints {
			parsed, err := url.Parse(endpoint.URL)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				continue
			}
			runtimeProvider.Endpoints = append(runtimeProvider.Endpoints, RuntimeEndpoint{
				URL:      parsed,
				Priority: endpoint.Priority,
				Weight:   endpoint.Weight,
				Adapter:  adapter,
			})
		}
		registry.providers[provider.Name] = runtimeProvider
	}
	return registry
}

func (r *ProviderRegistry) Get(provider string) (listeners.RuntimeProvider, bool) {
	p, ok := r.providers[strings.TrimSpace(provider)]
	if !ok {
		return listeners.RuntimeProvider{}, false
	}
	endpoints := make([]listeners.RuntimeEndpoint, 0, len(p.Endpoints))
	for _, ep := range p.Endpoints {
		endpoints = append(endpoints, listeners.RuntimeEndpoint{URL: ep.URL, Priority: ep.Priority, Adapter: ep.Adapter})
	}
	return listeners.RuntimeProvider{Name: p.Name, Endpoints: endpoints}, true
}

// EndpointSelector sorts endpoints so callers can apply failover in order.
type EndpointSelector struct{}

func NewEndpointSelector() *EndpointSelector { return &EndpointSelector{} }

func (s *EndpointSelector) Select(_ context.Context, provider listeners.RuntimeProvider, _ *http.Request) []listeners.RuntimeEndpoint {
	ordered := append([]listeners.RuntimeEndpoint{}, provider.Endpoints...)
	sort.SliceStable(ordered, func(i, j int) bool {
		left := providerPriority(provider, ordered[i])
		right := providerPriority(provider, ordered[j])
		if left == right {
			return describeEndpoint(ordered[i].URL) < describeEndpoint(ordered[j].URL)
		}
		return left < right
	})
	return ordered
}

func providerPriority(provider listeners.RuntimeProvider, endpoint listeners.RuntimeEndpoint) int {
	for _, ep := range provider.Endpoints {
		if describeEndpoint(ep.URL) == describeEndpoint(endpoint.URL) {
			return ep.Priority
		}
	}
	return 0
}

func ClassifyTimeout(err error) listeners.TimeoutClassification {
	if err == nil {
		return listeners.TimeoutClassification(TimeoutUnknown)
	}
	if strings.Contains(strings.ToLower(err.Error()), "deadline exceeded") {
		return listeners.TimeoutClassification(TimeoutDeadline)
	}
	type timeout interface{ Timeout() bool }
	if te, ok := err.(timeout); ok && te.Timeout() {
		if strings.Contains(strings.ToLower(err.Error()), "dial") || strings.Contains(strings.ToLower(err.Error()), "connect") {
			return listeners.TimeoutClassification(TimeoutConnect)
		}
		return listeners.TimeoutClassification(TimeoutTransient)
	}
	if strings.Contains(strings.ToLower(err.Error()), "timeout") {
		return listeners.TimeoutClassification(TimeoutTransient)
	}
	return listeners.TimeoutClassification(TimeoutUnknown)
}

func describeEndpoint(endpoint *url.URL) string {
	if endpoint == nil {
		return ""
	}
	return endpoint.String()
}
