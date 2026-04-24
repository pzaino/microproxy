package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadConfigFailsOnInvalidListener(t *testing.T) {
	tempFile := "test_invalid_listener.yaml"
	data := []byte(`
listeners:
  - name: bad
    type: http
    address: "not-an-address"
`)
	if err := os.WriteFile(tempFile, data, 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	defer os.Remove(tempFile)

	_, err := LoadConfig(tempFile)
	if err == nil {
		t.Fatal("expected config validation error")
	}

	if !strings.Contains(err.Error(), "listeners[0].address") {
		t.Fatalf("expected listener validation error, got %v", err)
	}
}

func TestValidateRequiresListener(t *testing.T) {
	cfg := NewConfig()
	cfg.Listeners = nil
	cfg.MicroProxy.HTTPProto = ""

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing listener validation error")
	}
}
