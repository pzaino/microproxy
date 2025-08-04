package config

import (
	"os"
	"testing"
)

func TestLoadYAMLConfig(t *testing.T) {
	tempFile := "test_config.yaml"
	data := []byte(`
upstream_proxy:
  proxies:
    - "http://proxy.example.com:8080"
  logins:
    - ip_range: "192.168.1.0/24"
      username: "user-${SESSION_ID}"
      password: "pass"
microproxy:
  http_proto: ":9090"
`)
	err := os.WriteFile(tempFile, data, 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	defer os.Remove(tempFile)

	cfg, err := LoadConfig(tempFile)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.MicroProxy.HTTPProto != ":9090" {
		t.Errorf("expected :9090, got %s", cfg.MicroProxy.HTTPProto)
	}

	if len(cfg.UpstreamProxy.Proxies) != 1 || cfg.UpstreamProxy.Proxies[0] != "http://proxy.example.com:8080" {
		t.Errorf("expected proxy 'http://proxy.example.com:8080', got %v", cfg.UpstreamProxy.Proxies)
	}

	if len(cfg.UpstreamProxy.Logins) != 1 {
		t.Fatalf("expected 1 login rule, got %d", len(cfg.UpstreamProxy.Logins))
	}

	login := cfg.UpstreamProxy.Logins[0]
	if login.IPRange != "192.168.1.0/24" {
		t.Errorf("expected IP range '192.168.1.0/24', got %s", login.IPRange)
	}
	if login.Username != "user-${SESSION_ID}" {
		t.Errorf("expected username 'user-${SESSION_ID}', got %s", login.Username)
	}
	if login.Password != "pass" {
		t.Errorf("expected password 'pass', got %s", login.Password)
	}
}
