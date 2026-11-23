package config

import (
	"strings"
	"testing"
)

func TestObservabilitySharedAddressValidation(t *testing.T) {
	t.Parallel()
	cfg := baseConfig()
	cfg.Observability.Metrics.Enabled = true
	cfg.Observability.Metrics.Address = "127.0.0.1:9090"
	cfg.Observability.HealthEndpoints.LivenessAddress = "127.0.0.1:9090"
	cfg.Observability.HealthEndpoints.ReadinessAddress = "127.0.0.1:9090"
	cfg.Observability.HealthEndpoints.StartupAddress = "127.0.0.1:9090"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("all observability routes should share one HTTP listener: %v", err)
	}
}

func TestBindConflictAddressOverlapCases(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		a, b  string
		allow bool
	}{
		{"different IPv4 bind addresses", "127.0.0.1:8080", "127.0.0.2:8080", true},
		{"duplicate IPv4 addresses", "127.0.0.1:8080", "127.0.0.1:8080", false},
		{"IPv4 wildcard overlaps loopback", "0.0.0.0:8080", "127.0.0.1:8080", false},
		{"IPv6 wildcard may overlap IPv4", "[::]:8080", "127.0.0.1:8080", false},
		{"IPv6 literal addresses", "[::1]:8080", "[::2]:8080", true},
		{"same port via service name", "127.0.0.1:http", "127.0.0.1:80", false},
		{"different TCP ports", "127.0.0.1:8080", "127.0.0.1:8082", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.Listeners[0].Address = tc.a
			cfg.Listeners[1].Address = tc.b
			err := cfg.Validate()
			if tc.allow && err != nil {
				t.Fatalf("distinct sockets should validate: %v", err)
			}
			if !tc.allow && err == nil {
				t.Fatal("expected bind conflict")
			}
		})
	}
}

func TestObservabilityAddressAliasStillConflicts(t *testing.T) {
	t.Parallel()
	cfg := baseConfig()
	cfg.Observability.Metrics.Enabled = true
	cfg.Observability.Metrics.Address = "127.0.0.1:http"
	cfg.Observability.HealthEndpoints.LivenessAddress = "127.0.0.1:80"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "observability.health_endpoints.liveness_address") {
		t.Fatalf("distinct address strings require two servers and must conflict: %v", err)
	}
}
