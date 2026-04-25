package dataplane

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/internal/dataplane/policy"
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
	Health   EndpointHealthSnapshot
}

type EndpointHealthState string

const (
	EndpointHealthHealthy   EndpointHealthState = "healthy"
	EndpointHealthDegraded  EndpointHealthState = "degraded"
	EndpointHealthUnhealthy EndpointHealthState = "unhealthy"
	EndpointHealthOpen      EndpointHealthState = "open"
	EndpointHealthHalfOpen  EndpointHealthState = "half-open"
)

type EndpointHealthSnapshot struct {
	State         EndpointHealthState `json:"state"`
	Reason        string              `json:"reason,omitempty"`
	UpdatedAt     time.Time           `json:"updated_at,omitempty"`
	LastSuccessAt time.Time           `json:"last_success_at,omitempty"`
	LastFailureAt time.Time           `json:"last_failure_at,omitempty"`
	LastProbeAt   time.Time           `json:"last_probe_at,omitempty"`
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
		Selector:          NewEndpointSelector(registry),
		ClassifyTimeoutFn: ClassifyTimeout,
		PolicyEvaluator:   policy.NewEngine(cfg),
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
	mu        sync.RWMutex
	providers map[string]RuntimeProvider
	health    map[string]map[string]*endpointHealthState
	probe     probeDialer
	now       func() time.Time
}

func NewProviderRegistry(cfg *config.Config) *ProviderRegistry {
	registry := &ProviderRegistry{
		providers: map[string]RuntimeProvider{},
		health:    map[string]map[string]*endpointHealthState{},
		probe:     &httpProbeDialer{},
		now:       time.Now,
	}
	if cfg == nil {
		return registry
	}
	adapterFactory := upstreamAdapterFactory{}

	for _, provider := range cfg.Providers {
		runtimeProvider := RuntimeProvider{Name: provider.Name}
		adapter := adapterFactory.ForProvider(provider)
		providerHealth := normalizeHealthConfig(provider.Health)
		registry.health[provider.Name] = map[string]*endpointHealthState{}
		for _, endpoint := range provider.Endpoints {
			parsed, err := url.Parse(endpoint.URL)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				continue
			}
			endpointState := newEndpointHealthState(providerHealth)
			registry.health[provider.Name][describeEndpoint(parsed)] = endpointState
			runtimeProvider.Endpoints = append(runtimeProvider.Endpoints, RuntimeEndpoint{
				URL:      parsed,
				Priority: endpoint.Priority,
				Weight:   endpoint.Weight,
				Adapter:  adapter,
				Health: EndpointHealthSnapshot{
					State: endpointState.state,
				},
			})
			if providerHealth.Enabled {
				go registry.startActiveProbe(provider.Name, parsed, providerHealth)
			}
		}
		registry.providers[provider.Name] = runtimeProvider
	}
	return registry
}

func (r *ProviderRegistry) Get(provider string) (listeners.RuntimeProvider, bool) {
	providerName := strings.TrimSpace(provider)
	r.mu.RLock()
	p, ok := r.providers[providerName]
	if !ok {
		r.mu.RUnlock()
		return listeners.RuntimeProvider{}, false
	}
	endpoints := make([]listeners.RuntimeEndpoint, 0, len(p.Endpoints))
	for _, ep := range p.Endpoints {
		key := describeEndpoint(ep.URL)
		snapshot := EndpointHealthSnapshot{State: EndpointHealthHealthy}
		if endpointState := r.health[providerName][key]; endpointState != nil {
			snapshot = endpointState.snapshot()
		}
		endpoints = append(endpoints, listeners.RuntimeEndpoint{
			URL:      ep.URL,
			Priority: ep.Priority,
			Adapter:  ep.Adapter,
			Health: listeners.EndpointHealthSnapshot{
				State:         string(snapshot.State),
				Reason:        snapshot.Reason,
				UpdatedAt:     snapshot.UpdatedAt,
				LastSuccessAt: snapshot.LastSuccessAt,
				LastFailureAt: snapshot.LastFailureAt,
				LastProbeAt:   snapshot.LastProbeAt,
			},
		})
	}
	r.mu.RUnlock()
	return listeners.RuntimeProvider{Name: p.Name, Endpoints: endpoints}, true
}

func (r *ProviderRegistry) SnapshotProviderHealth(provider string) []EndpointRuntimeHealth {
	r.mu.RLock()
	defer r.mu.RUnlock()
	runtimeProvider, ok := r.providers[strings.TrimSpace(provider)]
	if !ok {
		return nil
	}
	items := make([]EndpointRuntimeHealth, 0, len(runtimeProvider.Endpoints))
	for _, endpoint := range runtimeProvider.Endpoints {
		key := describeEndpoint(endpoint.URL)
		snapshot := EndpointHealthSnapshot{State: EndpointHealthHealthy}
		if state := r.health[runtimeProvider.Name][key]; state != nil {
			snapshot = state.snapshot()
		}
		items = append(items, EndpointRuntimeHealth{
			URL:      key,
			Priority: endpoint.Priority,
			Weight:   endpoint.Weight,
			Health:   snapshot,
		})
	}
	return items
}

func (r *ProviderRegistry) ObserveEndpointOutcome(provider string, endpoint *url.URL, err error, _ listeners.TimeoutClassification) {
	if endpoint == nil {
		return
	}
	now := r.now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.endpointStateLocked(provider, endpoint)
	if state == nil {
		return
	}
	if err == nil {
		state.passiveFailures = 0
		state.lastSuccessAt = now
		state.transition(EndpointHealthHealthy, "request succeeded", now)
		return
	}
	state.lastFailureAt = now
	state.passiveFailures++
	if state.passiveFailures >= state.cfg.FailureThreshold {
		state.openedAt = now
		state.transition(EndpointHealthOpen, "passive failure threshold reached", now)
		return
	}
	state.transition(EndpointHealthDegraded, "request failures observed", now)
}

func (r *ProviderRegistry) allowEndpoint(provider string, endpoint *url.URL, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.endpointStateLocked(provider, endpoint)
	if state == nil {
		return true
	}
	if !state.cfg.Enabled {
		return true
	}
	switch state.state {
	case EndpointHealthOpen:
		if now.Sub(state.openedAt) < state.halfOpenAfter() {
			return false
		}
		state.transition(EndpointHealthHalfOpen, "half-open trial window", now)
		return true
	case EndpointHealthUnhealthy:
		return false
	default:
		return true
	}
}

type EndpointSelector struct {
	registry *ProviderRegistry
}

func NewEndpointSelector(registry *ProviderRegistry) *EndpointSelector {
	return &EndpointSelector{registry: registry}
}

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
	if s.registry == nil {
		return ordered
	}
	filtered := make([]listeners.RuntimeEndpoint, 0, len(ordered))
	for _, endpoint := range ordered {
		if s.registry.allowEndpoint(provider.Name, endpoint.URL, s.registry.now().UTC()) {
			filtered = append(filtered, endpoint)
		}
	}
	return filtered
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

type EndpointRuntimeHealth struct {
	URL      string                 `json:"url"`
	Priority int                    `json:"priority"`
	Weight   int                    `json:"weight"`
	Health   EndpointHealthSnapshot `json:"health"`
}

type endpointHealthState struct {
	cfg                  config.ProviderHealthConfig
	state                EndpointHealthState
	reason               string
	updatedAt            time.Time
	lastSuccessAt        time.Time
	lastFailureAt        time.Time
	lastProbeAt          time.Time
	consecutiveProbeFail int
	passiveFailures      int
	openedAt             time.Time
}

func newEndpointHealthState(cfg config.ProviderHealthConfig) *endpointHealthState {
	return &endpointHealthState{cfg: cfg, state: EndpointHealthHealthy}
}

func (s *endpointHealthState) transition(state EndpointHealthState, reason string, at time.Time) {
	s.state = state
	s.reason = reason
	s.updatedAt = at
}

func (s *endpointHealthState) snapshot() EndpointHealthSnapshot {
	return EndpointHealthSnapshot{
		State:         s.state,
		Reason:        s.reason,
		UpdatedAt:     s.updatedAt,
		LastSuccessAt: s.lastSuccessAt,
		LastFailureAt: s.lastFailureAt,
		LastProbeAt:   s.lastProbeAt,
	}
}

func (s *endpointHealthState) halfOpenAfter() time.Duration {
	return time.Duration(s.cfg.IntervalSeconds*max(1, s.cfg.FailureThreshold)) * time.Second
}

func (r *ProviderRegistry) endpointStateLocked(provider string, endpoint *url.URL) *endpointHealthState {
	provider = strings.TrimSpace(provider)
	endpointKey := describeEndpoint(endpoint)
	stateByEndpoint, ok := r.health[provider]
	if !ok {
		return nil
	}
	return stateByEndpoint[endpointKey]
}

func normalizeHealthConfig(cfg config.ProviderHealthConfig) config.ProviderHealthConfig {
	if cfg.IntervalSeconds <= 0 {
		cfg.IntervalSeconds = 5
	}
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 2
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 3
	}
	return cfg
}

func (r *ProviderRegistry) startActiveProbe(provider string, endpoint *url.URL, cfg config.ProviderHealthConfig) {
	ticker := time.NewTicker(time.Duration(cfg.IntervalSeconds) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		r.probeOnce(provider, endpoint, cfg)
	}
}

func (r *ProviderRegistry) probeOnce(provider string, endpoint *url.URL, cfg config.ProviderHealthConfig) {
	now := r.now().UTC()
	target := *endpoint
	if cfg.CheckPath != "" {
		target.Path = cfg.CheckPath
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	err := r.probe.Probe(target.String(), timeout)

	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.endpointStateLocked(provider, endpoint)
	if state == nil {
		return
	}
	state.lastProbeAt = now
	if err == nil {
		state.consecutiveProbeFail = 0
		state.passiveFailures = 0
		state.lastSuccessAt = now
		if state.state != EndpointHealthOpen {
			state.transition(EndpointHealthHealthy, "active probe succeeded", now)
		}
		return
	}
	state.lastFailureAt = now
	state.consecutiveProbeFail++
	if state.consecutiveProbeFail >= cfg.FailureThreshold {
		state.transition(EndpointHealthUnhealthy, "active probe failure threshold reached", now)
		return
	}
	state.transition(EndpointHealthDegraded, "active probe failures observed", now)
}

type probeDialer interface {
	Probe(endpoint string, timeout time.Duration) error
}

type httpProbeDialer struct{}

func (h *httpProbeDialer) Probe(endpoint string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= http.StatusInternalServerError {
		return errors.New("probe status failure")
	}
	return nil
}
