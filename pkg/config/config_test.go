package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var sessionIDPattern = regexp.MustCompile(`^session-[A-Za-z0-9_-]+$`)

func writeTempConfigFile(t *testing.T, dir, ext, data string) string {
	t.Helper()

	file := filepath.Join(dir, fmt.Sprintf("config%s", ext))
	if err := os.WriteFile(file, []byte(data), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	return file
}

func TestConfigLoadDecodingAndLegacyCompatibility(t *testing.T) {
	tests := []struct {
		name    string
		ext     string
		content string
	}{
		{
			name: "json",
			ext:  ".json",
			content: `{
  "upstream_proxy": {
    "proxies": ["http://proxy.example.com:8080"],
    "logins": [{
      "ip_range": "192.168.1.0/24",
      "username": "user-${SESSION_ID}",
      "password": "pass"
    }]
  },
  "microproxy": {
    "http_proto": ":9090"
  }
}`,
		},
		{
			name: "yaml",
			ext:  ".yaml",
			content: `
upstream_proxy:
  proxies:
    - "http://proxy.example.com:8080"
  logins:
    - ip_range: "192.168.1.0/24"
      username: "user-${SESSION_ID}"
      password: "pass"
microproxy:
  http_proto: ":9090"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTempConfigFile(t, dir, tt.ext, tt.content)

			cfg := NewConfig()
			if err := cfg.Load(path); err != nil {
				t.Fatalf("failed to load config: %v", err)
			}

			if cfg.SchemaVersion != defaultSchemaVersion {
				t.Fatalf("expected schema version %q, got %q", defaultSchemaVersion, cfg.SchemaVersion)
			}
			if cfg.MicroProxy.HTTPProto != ":9090" {
				t.Fatalf("expected :9090, got %s", cfg.MicroProxy.HTTPProto)
			}
			if len(cfg.Listeners) != 1 || cfg.Listeners[0].Address != ":9090" {
				t.Fatalf("expected legacy listener mapped to :9090, got %+v", cfg.Listeners)
			}
			if len(cfg.Providers) != 1 || cfg.Providers[0].Endpoints[0].URL != "http://proxy.example.com:8080" {
				t.Fatalf("expected proxy mapped into provider endpoint, got %+v", cfg.Providers)
			}
			if len(cfg.Policies) != 1 || cfg.Policies[0].Parameters["username"] != "user-${SESSION_ID}" {
				t.Fatalf("expected login rule mapped into policy, got %+v", cfg.Policies)
			}
		})
	}
}

func TestNewConfigDefaults(t *testing.T) {
	cfg := NewConfig()

	if cfg.SchemaVersion != defaultSchemaVersion {
		t.Fatalf("expected schema version %q, got %q", defaultSchemaVersion, cfg.SchemaVersion)
	}

	if cfg.MicroProxy.HTTPProto != "0.0.0.0:8080" {
		t.Fatalf("expected default HTTP listener address, got %q", cfg.MicroProxy.HTTPProto)
	}
	if cfg.MicroProxy.RateLimit != 100 {
		t.Fatalf("expected default rate limit 100, got %d", cfg.MicroProxy.RateLimit)
	}

	if cfg.Listeners == nil || cfg.Providers == nil || cfg.Policies == nil || cfg.Tenants == nil {
		t.Fatalf("expected default slices to be initialized")
	}
	if cfg.UpstreamProxy.Proxies == nil {
		t.Fatalf("expected upstream proxies slice to be initialized")
	}
}

func TestConfigLoadUnsupportedExtension(t *testing.T) {
	dir := t.TempDir()
	path := writeTempConfigFile(t, dir, ".toml", `schema_version = "1"`)

	cfg := NewConfig()
	err := cfg.Load(path)
	if err == nil {
		t.Fatal("expected unsupported extension error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported config file format: .toml") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigLoadEmptyFilename(t *testing.T) {
	cfg := NewConfig()
	before := *cfg

	if err := cfg.Load("   "); err != nil {
		t.Fatalf("expected nil error for empty filename, got %v", err)
	}

	if !reflect.DeepEqual(before, *cfg) {
		t.Fatalf("expected config unchanged for empty filename")
	}
}

func TestGetCredentialsFor(t *testing.T) {
	cfg := UpstreamProxyConfig{
		Logins: []LoginRule{
			{IPRange: "invalid", Username: "ignored", Password: "ignored"},
			{IPRange: "192.168.1.0/24", Username: "user-${SESSION_ID}", Password: "pass"},
		},
	}

	tests := []struct {
		name         string
		ip           string
		wantPassword string
		wantMatch    bool
	}{
		{name: "matching subnet", ip: "192.168.1.8", wantPassword: "pass", wantMatch: true},
		{name: "non matching subnet", ip: "10.0.0.1", wantPassword: "", wantMatch: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, password := cfg.GetCredentialsFor(net.ParseIP(tt.ip))
			if password != tt.wantPassword {
				t.Fatalf("expected password %q, got %q", tt.wantPassword, password)
			}

			if tt.wantMatch {
				if !strings.HasPrefix(username, "user-session-") {
					t.Fatalf("expected session id substitution in username, got %q", username)
				}
			} else if username != "" {
				t.Fatalf("expected empty username for non-match, got %q", username)
			}
		})
	}
}

func TestGenerateSessionIDFormat(t *testing.T) {
	sessionID := generateSessionID()

	if !strings.HasPrefix(sessionID, sessionIDPrefix) {
		t.Fatalf("expected session id to start with %q, got %q", sessionIDPrefix, sessionID)
	}

	if !sessionIDPattern.MatchString(sessionID) {
		t.Fatalf("expected session id to match url-safe charset, got %q", sessionID)
	}

	wantLen := len(sessionIDPrefix) + 22 // base64.RawURLEncoding length for 16 random bytes.
	if len(sessionID) != wantLen {
		t.Fatalf("expected session id length %d, got %d (%q)", wantLen, len(sessionID), sessionID)
	}
}

func TestResolveSessionIDReplacementSemantics(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		assertFn func(t *testing.T, got string)
	}{
		{
			name:  "all placeholders replaced with same generated value",
			input: "user:${SESSION_ID}:region:${SESSION_ID}",
			assertFn: func(t *testing.T, got string) {
				t.Helper()
				if strings.Contains(got, "${SESSION_ID}") {
					t.Fatalf("expected placeholders to be replaced, got %q", got)
				}

				matches := regexp.MustCompile(`session-[A-Za-z0-9_-]+`).FindAllString(got, -1)
				if len(matches) != 2 {
					t.Fatalf("expected 2 substituted session ids, got %d in %q", len(matches), got)
				}
				if matches[0] != matches[1] {
					t.Fatalf("expected same session id reused for all placeholders, got %q and %q", matches[0], matches[1])
				}
			},
		},
		{
			name:  "no placeholder leaves username unchanged",
			input: "user-static",
			assertFn: func(t *testing.T, got string) {
				t.Helper()
				if got != "user-static" {
					t.Fatalf("expected unchanged username, got %q", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertFn(t, resolveSessionID(tt.input))
		})
	}
}
