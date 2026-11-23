package config

import (
	"path/filepath"
	"testing"
)

// TestDeployExampleConfigsValidate keeps the shipped deployment examples on the
// same validation path as an operator's config.yaml. The examples reference
// environment placeholders, so provide non-secret test values before loading.
func TestDeployExampleConfigsValidate(t *testing.T) {
	t.Setenv("MICROPROXY_SESSION_API_KEY", "test-session-api-key")
	t.Setenv("MICROPROXY_HTTP_PROXY_USER", "test-user")
	t.Setenv("MICROPROXY_HTTP_PROXY_PASSWORD", "test-password")
	t.Setenv("MICROPROXY_LISTENER_USER", "test-listener-user")
	t.Setenv("MICROPROXY_LISTENER_PASSWORD", "test-listener-password")
	t.Setenv("MICROPROXY_UPSTREAM_ENDPOINT", "http://upstream-proxy.example:3128")
	t.Setenv("MICROPROXY_UPSTREAM_USER", "test-user")
	t.Setenv("MICROPROXY_UPSTREAM_PASSWORD", "test-password")

	for _, name := range []string{
		"config.example.yaml",
		"config.vdi.container.example.yaml",
	} {
		name := name
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "deploy", name)
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatalf("load %s: %v", name, err)
			}
			if !cfg.SessionControl.Enabled {
				t.Fatalf("%s must enable the session control example", name)
			}
			if cfg.SessionControl.Provider == "" {
				t.Fatalf("%s must name the sticky provider", name)
			}
		})
	}
}
