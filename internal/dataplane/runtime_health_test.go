package dataplane

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/pkg/config"
)

type fakeProbeDialer struct {
	errs []error
}

func (f *fakeProbeDialer) Probe(_ string, _ time.Duration) error {
	if len(f.errs) == 0 {
		return nil
	}
	err := f.errs[0]
	f.errs = f.errs[1:]
	return err
}

type timeoutError struct{ msg string }

func (t timeoutError) Error() string   { return t.msg }
func (t timeoutError) Timeout() bool   { return true }
func (t timeoutError) Temporary() bool { return true }

func TestProviderRegistryProbeTransitions(t *testing.T) {
	cfg := &config.Config{Providers: []config.ProviderConfig{{
		Name:      "provider-a",
		Type:      "direct",
		Endpoints: []config.ProviderEndpoint{{URL: "http://provider-a.example"}},
		Health:    config.ProviderHealthConfig{Enabled: false, CheckPath: "/healthz", IntervalSeconds: 1, TimeoutSeconds: 1, FailureThreshold: 2},
	}}}
	registry := NewProviderRegistry(cfg)

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	registry.now = func() time.Time { return now }
	registry.probe = &fakeProbeDialer{errs: []error{errors.New("dial timeout"), errors.New("dial timeout"), nil}}

	endpoint, _ := url.Parse("http://provider-a.example")
	healthCfg := normalizeHealthConfig(cfg.Providers[0].Health)

	registry.probeOnce("provider-a", endpoint, healthCfg)
	snapshot := registry.SnapshotProviderHealth("provider-a")
	if got := snapshot[0].Health.State; got != EndpointHealthDegraded {
		t.Fatalf("expected degraded after first probe failure, got %q", got)
	}

	now = now.Add(time.Second)
	registry.probeOnce("provider-a", endpoint, healthCfg)
	snapshot = registry.SnapshotProviderHealth("provider-a")
	if got := snapshot[0].Health.State; got != EndpointHealthUnhealthy {
		t.Fatalf("expected unhealthy after threshold probe failures, got %q", got)
	}

	now = now.Add(time.Second)
	registry.probeOnce("provider-a", endpoint, healthCfg)
	snapshot = registry.SnapshotProviderHealth("provider-a")
	if got := snapshot[0].Health.State; got != EndpointHealthHealthy {
		t.Fatalf("expected healthy after probe recovery, got %q", got)
	}
}

func TestEndpointSelectorSkipsOpenAndAllowsHalfOpenTrial(t *testing.T) {
	cfg := &config.Config{Providers: []config.ProviderConfig{{
		Name: "provider-a",
		Type: "direct",
		Endpoints: []config.ProviderEndpoint{
			{URL: "http://primary.example", Priority: 1},
			{URL: "http://secondary.example", Priority: 2},
		},
		Health: config.ProviderHealthConfig{Enabled: true, IntervalSeconds: 1, TimeoutSeconds: 1, FailureThreshold: 2},
	}}}
	registry := NewProviderRegistry(cfg)
	now := time.Date(2026, 4, 25, 12, 30, 0, 0, time.UTC)
	registry.now = func() time.Time { return now }

	primary, _ := url.Parse("http://primary.example")
	registry.ObserveEndpointOutcome("provider-a", primary, timeoutError{msg: "connect timeout"}, listeners.TimeoutClassification(TimeoutConnect))
	registry.ObserveEndpointOutcome("provider-a", primary, timeoutError{msg: "connect timeout"}, listeners.TimeoutClassification(TimeoutConnect))

	provider, ok := registry.Get("provider-a")
	if !ok {
		t.Fatalf("expected provider in registry")
	}
	selector := NewEndpointSelector(registry)
	selected := selector.Select(t.Context(), provider, &http.Request{})
	if len(selected) != 1 || selected[0].URL.String() != "http://secondary.example" {
		t.Fatalf("expected only secondary endpoint while primary is open, got %+v", selected)
	}

	now = now.Add(3 * time.Second)
	provider, _ = registry.Get("provider-a")
	selected = selector.Select(t.Context(), provider, &http.Request{})
	if len(selected) != 2 {
		t.Fatalf("expected half-open trial to re-include primary endpoint, got %d endpoints", len(selected))
	}
	if got := selected[0].URL.String(); got != "http://primary.example" {
		t.Fatalf("expected primary endpoint to lead half-open trial, got %q", got)
	}
}
