package config

// File: config_test.go

import (
	"os"
	"testing"
)

func TestLoadYAMLConfig(t *testing.T) {
	tempFile := "test_config.yaml"
	data := []byte(`
upstream_proxy:
  upstream_proxy: "http://proxy.example.com:8080"
  username: "user"
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
	if cfg.UpstreamProxy.Username != "user" {
		t.Errorf("expected username 'user', got %s", cfg.UpstreamProxy.Username)
	}
}
