package main

import (
	"strings"
	"testing"
	"time"

	"github.com/pzaino/microproxy/pkg/config"
)

func TestShutdownTimeout(t *testing.T) {
	if shutdownTimeout != 10*time.Second {
		t.Fatalf("expected shutdownTimeout to be 10s, got %v", shutdownTimeout)
	}
}

func healthTestConfig() *config.Config {
	cfg := &config.Config{
		SchemaVersion: "1",
		Listeners: []config.ListenerConfig{
			{Name: "edge-http", Type: "http", Address: "127.0.0.1:0", AuthType: "none", Enabled: true},
		},
		Observability: config.ObservabilityConfig{
			HealthEndpoints: config.HealthEndpointsConfig{
				LivenessAddress:  "127.0.0.1:9191",
				ReadinessAddress: "127.0.0.1:9192",
			},
		},
	}
	return cfg
}

func TestApplyHealthAddressOverride_EmptyLeavesYAMLValue(t *testing.T) {
	cfg := healthTestConfig()
	if err := applyHealthAddressOverride(cfg, ""); err != nil {
		t.Fatalf("empty override must not fail: %v", err)
	}
	if got := cfg.Observability.HealthEndpoints.LivenessAddress; got != "127.0.0.1:9191" {
		t.Fatalf("empty override must preserve YAML liveness address, got %q", got)
	}

	if err := applyHealthAddressOverride(cfg, "   "); err != nil {
		t.Fatalf("blank override must not fail: %v", err)
	}
	if got := cfg.Observability.HealthEndpoints.LivenessAddress; got != "127.0.0.1:9191" {
		t.Fatalf("blank override must preserve YAML liveness address, got %q", got)
	}
}

func TestApplyHealthAddressOverride_AppliesExplicitValue(t *testing.T) {
	cfg := healthTestConfig()
	if err := applyHealthAddressOverride(cfg, "127.0.0.1:9292"); err != nil {
		t.Fatalf("override failed: %v", err)
	}
	if got := cfg.Observability.HealthEndpoints.LivenessAddress; got != "127.0.0.1:9292" {
		t.Fatalf("expected override to take precedence, got %q", got)
	}
}

func TestApplyHealthAddressOverride_RejectsInvalidAddress(t *testing.T) {
	cfg := healthTestConfig()
	err := applyHealthAddressOverride(cfg, "not-an-address")
	if err == nil {
		t.Fatal("expected invalid address error")
	}
	if !strings.Contains(err.Error(), "-health-addr") || !strings.Contains(err.Error(), "liveness_address") {
		t.Fatalf("expected clear override error, got %v", err)
	}
}

func TestApplyHealthAddressOverride_RejectsConflicts(t *testing.T) {
	// The health server cannot share a socket with an independent proxy server.
	cfg := healthTestConfig()
	cfg.Listeners = append(cfg.Listeners, config.ListenerConfig{
		Name: "edge-extra", Type: "http", Address: "127.0.0.1:9393", AuthType: "none", Enabled: true,
	})
	err := applyHealthAddressOverride(cfg, "127.0.0.1:9393")
	if err == nil {
		t.Fatal("expected conflict with an enabled proxy listener")
	}
	if !strings.Contains(err.Error(), "-health-addr") {
		t.Fatalf("expected override context in error, got %v", err)
	}
}

func TestApplyHealthAddressOverride_AllowsSharedObservability(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{
			name: "other health endpoint",
			mutate: func(cfg *config.Config) {
				cfg.Observability.HealthEndpoints.ReadinessAddress = "127.0.0.1:9393"
			},
		},
		{
			name: "metrics",
			mutate: func(cfg *config.Config) {
				cfg.Observability.Metrics.Enabled = true
				cfg.Observability.Metrics.Address = "127.0.0.1:9393"
			},
		},
		{
			name: "all observability endpoints",
			mutate: func(cfg *config.Config) {
				cfg.Observability.Metrics.Enabled = true
				cfg.Observability.Metrics.Address = "127.0.0.1:9393"
				cfg.Observability.HealthEndpoints.ReadinessAddress = "127.0.0.1:9393"
				cfg.Observability.HealthEndpoints.StartupAddress = "127.0.0.1:9393"
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := healthTestConfig()
			tc.mutate(cfg)
			if err := applyHealthAddressOverride(cfg, "127.0.0.1:9393"); err != nil {
				t.Fatalf("observability handlers should share one HTTP listener: %v", err)
			}
			if got := cfg.Observability.HealthEndpoints.LivenessAddress; got != "127.0.0.1:9393" {
				t.Fatalf("expected CLI liveness override, got %q", got)
			}
		})
	}
}

func TestApplyHealthAddressOverride_RejectsSessionControlConflict(t *testing.T) {
	cfg := healthTestConfig()
	cfg.Providers = []config.ProviderConfig{
		{
			Name:      "sticky",
			Type:      "http_proxy",
			Auth:      config.ProviderAuthConfig{Type: "basic", Username: "u", Password: "p"},
			Endpoints: []config.ProviderEndpoint{{URL: "http://upstream.example:3128"}},
			Session: config.ProviderSessionConfig{
				Supported:        true,
				Mode:             "username_template",
				UsernameTemplate: "{{username}}-session-{{session_id}}",
			},
		},
	}
	cfg.SessionControl = config.SessionControlConfig{
		Enabled:     true,
		Address:     "127.0.0.1:9393",
		BearerToken: "token",
		Provider:    "sticky",
	}
	err := applyHealthAddressOverride(cfg, "127.0.0.1:9393")
	if err == nil {
		t.Fatal("expected session control conflict")
	}
	if !strings.Contains(err.Error(), "session_control.address") {
		t.Fatalf("expected session control conflict detail, got %v", err)
	}
}
