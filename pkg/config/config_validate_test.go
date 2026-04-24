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

func TestValidateAggregatesFieldLevelErrors(t *testing.T) {
	cfg := &Config{
		SchemaVersion: "1",
		Listeners: []ListenerConfig{
			{
				Name:    "public",
				Type:    "http",
				Address: "bad-addr",
				Enabled: true,
			},
			{
				Name:    "public",
				Type:    "https",
				Address: ":8443",
				Enabled: true,
			},
		},
		Providers: []ProviderConfig{
			{
				Name: "p1",
				Type: "http_proxy",
				Auth: ProviderAuthConfig{Type: "basic"},
				Endpoints: []ProviderEndpoint{
					{URL: "://bad-url", Priority: -1},
				},
			},
		},
		Routing: RoutingConfig{
			DefaultProvider: "missing-provider",
		},
		Tenants: []TenantConfig{
			{Name: "tenant-a", ID: "t-1"},
			{Name: "tenant-b", ID: "t-1"},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}

	verrs, ok := err.(*ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T", err)
	}

	if len(verrs.Errors) < 5 {
		t.Fatalf("expected aggregated errors, got %d: %v", len(verrs.Errors), verrs.Errors)
	}

	msg := err.Error()
	for _, expected := range []string{
		"listeners[0].address",
		"listeners[1].tls",
		"providers[0].auth.username",
		"routing.default_provider",
		"tenants[1].id",
	} {
		if !strings.Contains(msg, expected) {
			t.Fatalf("expected %q in validation message, got %q", expected, msg)
		}
	}
}
