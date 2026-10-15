package config

import (
	"strings"
	"testing"
)

func stickyProvider(name string) ProviderConfig {
	return ProviderConfig{
		Name: name,
		Type: "http_proxy",
		Auth: ProviderAuthConfig{Type: "basic", Username: "base-user", Password: "base-pass"},
		Endpoints: []ProviderEndpoint{{URL: "http://upstream.example:3128", Priority: 100}},
		Session: ProviderSessionConfig{
			Supported:        true,
			Mode:             "username_template",
			UsernameTemplate: "{{username}}-session-{{session_id}}",
		},
		Health: ProviderHealthConfig{Enabled: false},
	}
}

func baseConfig() *Config {
	return &Config{
		SchemaVersion: "1",
		Listeners: []ListenerConfig{
			{Name: "edge-http", Type: "http", Address: "0.0.0.0:8080", AuthType: "none", Enabled: true, Provider: "rotating"},
			{Name: "edge-http-sticky", Type: "http", Address: "0.0.0.0:8081", AuthType: "none", Enabled: true, Provider: "sticky"},
		},
		Providers: []ProviderConfig{
			{
				Name:      "rotating",
				Type:      "http_proxy",
				Auth:      ProviderAuthConfig{Type: "basic", Username: "rot-user", Password: "rot-pass"},
				Endpoints: []ProviderEndpoint{{URL: "http://upstream.example:3128"}},
				Health:    ProviderHealthConfig{Enabled: false},
			},
			stickyProvider("sticky"),
		},
		Routing: RoutingConfig{DefaultProvider: "rotating"},
		SessionControl: SessionControlConfig{
			Enabled:     true,
			Address:     "127.0.0.1:8094",
			BearerToken: "test-secret-token",
			Provider:    "sticky",
		},
	}
}

func TestValidateUsernameTemplate(t *testing.T) {
	t.Parallel()
	valid := []string{
		"{{username}}-session-{{session_id}}",
		"prefix-{{username}}-{{session_id}}-suffix",
	}
	for _, tmpl := range valid {
		if err := ValidateUsernameTemplate(tmpl); err != nil {
			t.Fatalf("expected valid template %q, got %v", tmpl, err)
		}
	}
	invalid := []string{
		"",
		"{{username}}",
		"{{session_id}}",
		"{{username}}-{{unknown}}",
		"{{username}-session-{{session_id}}",
		"${USER}-session-{{session_id}}",
		"{{username}}-session-${SESSION}",
	}
	for _, tmpl := range invalid {
		if err := ValidateUsernameTemplate(tmpl); err == nil {
			t.Fatalf("expected invalid template %q to fail", tmpl)
		}
	}
}

func TestRenderUsername(t *testing.T) {
	t.Parallel()
	got, err := RenderUsername("{{username}}-session-{{session_id}}", "zone-user", "abc123")
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	if got != "zone-user-session-abc123" {
		t.Fatalf("unexpected render %q", got)
	}
	if _, err := RenderUsername("{{username}}-session-{{session_id}}", "", "abc"); err == nil {
		t.Fatal("expected empty base username to fail")
	}
}

func TestListenerProviderBindingValidation(t *testing.T) {
	t.Parallel()
	cfg := baseConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid sticky config, got %v", err)
	}

	cfg.Listeners[0].Provider = "missing-provider"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "listeners[0].provider") {
		t.Fatalf("expected listener provider reference error, got %v", err)
	}
}

func TestListenerDuplicateAddressRejected(t *testing.T) {
	t.Parallel()
	cfg := baseConfig()
	cfg.Listeners[1].Address = "0.0.0.0:8080"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "listeners[1].address") {
		t.Fatalf("expected duplicate address error, got %v", err)
	}
}

func TestSessionValidationRejectsUnsupportedTypes(t *testing.T) {
	t.Parallel()
	for _, typ := range []string{"direct", "socks5_proxy"} {
		p := stickyProvider("p1")
		p.Type = typ
		if err := p.Session.Validate("providers[0].session", p); err == nil {
			t.Fatalf("expected session rejection for type %q", typ)
		}
	}
}

func TestSessionValidationRequiresBasicAuth(t *testing.T) {
	t.Parallel()
	p := stickyProvider("p1")
	p.Auth = ProviderAuthConfig{Type: "none"}
	if err := p.Session.Validate("providers[0].session", p); err == nil {
		t.Fatal("expected basic auth requirement error")
	}
	p = stickyProvider("p1")
	p.Auth = ProviderAuthConfig{Type: "basic", Username: "", Password: "x"}
	if err := p.Session.Validate("providers[0].session", p); err == nil {
		t.Fatal("expected base username requirement error")
	}
}

func TestSessionControlValidation(t *testing.T) {
	t.Parallel()
	cfg := baseConfig()
	cfg.SessionControl.BearerToken = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "session_control.bearer_token") {
		t.Fatalf("expected missing token error, got %v", err)
	}

	cfg = baseConfig()
	cfg.SessionControl.Provider = "rotating"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "session_control.provider") {
		t.Fatalf("expected non-session provider error, got %v", err)
	}

	cfg = baseConfig()
	cfg.SessionControl.Address = "127.0.0.1:8080"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "session_control.address") {
		t.Fatalf("expected port collision error, got %v", err)
	}

	// Disabled control plane carries no requirements.
	cfg = baseConfig()
	cfg.SessionControl = SessionControlConfig{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected disabled session_control to validate, got %v", err)
	}
}

func TestLegacyConfigWithoutNewFieldsStillValid(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		SchemaVersion: "1",
		Listeners: []ListenerConfig{
			{Name: "edge", Type: "http", Address: "0.0.0.0:8080", AuthType: "none", Enabled: true},
		},
		Providers: []ProviderConfig{
			{
				Name:      "p1",
				Type:      "http_proxy",
				Auth:      ProviderAuthConfig{Type: "basic", Username: "u", Password: "p"},
				Endpoints: []ProviderEndpoint{{URL: "http://upstream.example:3128"}},
			},
		},
		Routing: RoutingConfig{DefaultProvider: "p1"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected legacy config to remain valid, got %v", err)
	}
}
