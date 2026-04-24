package config

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

const defaultSchemaVersion = "1"

// Config holds the configuration for the proxy server.
//
// New typed sections are available at the root level:
// listeners, providers, routing, policies, tenants, and observability.
//
// Legacy sections (microproxy, upstream_proxy) are still accepted for one major cycle.
type Config struct {
	SchemaVersion string `json:"schema_version" yaml:"schema_version"`

	Listeners     []ListenerConfig    `json:"listeners" yaml:"listeners"`
	Providers     []ProviderConfig    `json:"providers" yaml:"providers"`
	Routing       RoutingConfig       `json:"routing" yaml:"routing"`
	Policies      []PolicyConfig      `json:"policies" yaml:"policies"`
	Tenants       []TenantConfig      `json:"tenants" yaml:"tenants"`
	Observability ObservabilityConfig `json:"observability" yaml:"observability"`

	// Legacy config sections.
	MicroProxy    ProxyConfig         `json:"microproxy" yaml:"microproxy"`
	UpstreamProxy UpstreamProxyConfig `json:"upstream_proxy" yaml:"upstream_proxy"`
}

// ListenerConfig defines a listener endpoint.
type ListenerConfig struct {
	Name      string     `json:"name" yaml:"name"`
	Type      string     `json:"type" yaml:"type"` // http, https, socks5
	Address   string     `json:"address" yaml:"address"`
	TLS       *TLSConfig `json:"tls,omitempty" yaml:"tls,omitempty"`
	RateLimit int        `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`
	AuthType  string     `json:"auth_type,omitempty" yaml:"auth_type,omitempty"`
	Enabled   bool       `json:"enabled" yaml:"enabled"`
}

type TLSConfig struct {
	CertFile string `json:"cert_file" yaml:"cert_file"`
	KeyFile  string `json:"key_file" yaml:"key_file"`
}

// ProviderConfig defines a typed upstream provider.
type ProviderConfig struct {
	Name         string               `json:"name" yaml:"name"`
	Type         string               `json:"type" yaml:"type"`
	Auth         ProviderAuthConfig   `json:"auth" yaml:"auth"`
	Endpoints    []ProviderEndpoint   `json:"endpoints" yaml:"endpoints"`
	Capabilities []string             `json:"capabilities" yaml:"capabilities"`
	Health       ProviderHealthConfig `json:"health" yaml:"health"`
}

type ProviderAuthConfig struct {
	Type     string            `json:"type" yaml:"type"` // none, basic, bearer, api_key
	Username string            `json:"username,omitempty" yaml:"username,omitempty"`
	Password string            `json:"password,omitempty" yaml:"password,omitempty"`
	Token    string            `json:"token,omitempty" yaml:"token,omitempty"`
	Headers  map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
}

type ProviderEndpoint struct {
	URL      string `json:"url" yaml:"url"`
	Priority int    `json:"priority,omitempty" yaml:"priority,omitempty"`
	Weight   int    `json:"weight,omitempty" yaml:"weight,omitempty"`
}

type ProviderHealthConfig struct {
	Enabled          bool   `json:"enabled" yaml:"enabled"`
	CheckPath        string `json:"check_path,omitempty" yaml:"check_path,omitempty"`
	IntervalSeconds  int    `json:"interval_seconds,omitempty" yaml:"interval_seconds,omitempty"`
	TimeoutSeconds   int    `json:"timeout_seconds,omitempty" yaml:"timeout_seconds,omitempty"`
	FailureThreshold int    `json:"failure_threshold,omitempty" yaml:"failure_threshold,omitempty"`
}

type RoutingConfig struct {
	DefaultProvider string        `json:"default_provider,omitempty" yaml:"default_provider,omitempty"`
	Rules           []RoutingRule `json:"rules,omitempty" yaml:"rules,omitempty"`
}

type RoutingRule struct {
	Name      string            `json:"name" yaml:"name"`
	Match     map[string]string `json:"match,omitempty" yaml:"match,omitempty"`
	Provider  string            `json:"provider" yaml:"provider"`
	PolicyRef string            `json:"policy_ref,omitempty" yaml:"policy_ref,omitempty"`
}

type PolicyConfig struct {
	Name       string            `json:"name" yaml:"name"`
	Type       string            `json:"type" yaml:"type"`
	Action     string            `json:"action" yaml:"action"`
	Selectors  map[string]string `json:"selectors,omitempty" yaml:"selectors,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

type TenantConfig struct {
	Name      string   `json:"name" yaml:"name"`
	ID        string   `json:"id" yaml:"id"`
	Providers []string `json:"providers,omitempty" yaml:"providers,omitempty"`
	Policies  []string `json:"policies,omitempty" yaml:"policies,omitempty"`
}

type ObservabilityConfig struct {
	AccessLog       AccessLogConfig       `json:"access_log" yaml:"access_log"`
	Metrics         MetricsConfig         `json:"metrics" yaml:"metrics"`
	Tracing         TracingConfig         `json:"tracing" yaml:"tracing"`
	HealthEndpoints HealthEndpointsConfig `json:"health_endpoints" yaml:"health_endpoints"`
}

type AccessLogConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Format  string `json:"format,omitempty" yaml:"format,omitempty"`
}

type MetricsConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Address string `json:"address,omitempty" yaml:"address,omitempty"`
}

type TracingConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	Exporter string `json:"exporter,omitempty" yaml:"exporter,omitempty"`
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
}

type HealthEndpointsConfig struct {
	LivenessAddress  string `json:"liveness_address,omitempty" yaml:"liveness_address,omitempty"`
	ReadinessAddress string `json:"readiness_address,omitempty" yaml:"readiness_address,omitempty"`
}

// ProxyConfig holds the legacy listener configuration.
type ProxyConfig struct {
	SOCKS5Proto string `json:"socks5_proto" yaml:"socks5_proto"`
	HTTPProto   string `json:"http_proto" yaml:"http_proto"`
	HTTPSProto  string `json:"https_proto" yaml:"https_proto"`
	CertFile    string `json:"cert_file" yaml:"cert_file"`
	KeyFile     string `json:"key_file" yaml:"key_file"`
	RateLimit   int    `json:"rate_limit" yaml:"rate_limit"`
	AuthType    string `json:"auth_type" yaml:"auth_type"`
}

type LoginRule struct {
	IPRange  string `json:"ip_range" yaml:"ip_range"` // e.g. "192.168.1.0/24"
	Username string `json:"username" yaml:"username"` // supports ${SESSION_ID} placeholder
	Password string `json:"password" yaml:"password"` // optional, can be empty
}

type UpstreamProxyConfig struct {
	Proxies []string    `json:"proxies" yaml:"proxies"` // list of proxy URLs
	Logins  []LoginRule `json:"logins" yaml:"logins"`   // login rules by client subnet
}

func (cfg *UpstreamProxyConfig) GetCredentialsFor(ip net.IP) (string, string) {
	for _, rule := range cfg.Logins {
		_, ipNet, err := net.ParseCIDR(rule.IPRange)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return resolveSessionID(rule.Username), rule.Password
		}
	}
	return "", ""
}

func resolveSessionID(username string) string {
	return strings.ReplaceAll(username, "${SESSION_ID}", generateSessionID())
}

func generateSessionID() string {
	return fmt.Sprintf("session-%d", rand.Intn(99999999))
}

// NewConfig returns a new Config instance.
func NewConfig() *Config {
	return &Config{
		SchemaVersion: defaultSchemaVersion,
		Listeners:     []ListenerConfig{},
		Providers:     []ProviderConfig{},
		Policies:      []PolicyConfig{},
		Tenants:       []TenantConfig{},
		MicroProxy: ProxyConfig{
			SOCKS5Proto: "",
			HTTPProto:   "0.0.0.0:8080",
			HTTPSProto:  "",
			CertFile:    "",
			KeyFile:     "",
			RateLimit:   100,
			AuthType:    "",
		},
		UpstreamProxy: UpstreamProxyConfig{
			Proxies: []string{},
		},
	}
}

// LoadConfig loads the configuration from the given file.
func LoadConfig(file string) (*Config, error) {
	c := NewConfig()
	err := c.Load(file)
	if err != nil {
		return nil, err
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}

	return c, nil
}

// Load loads the configuration from the given file.
func (c *Config) Load(file string) error {
	file = strings.TrimSpace(file)
	if file == "" {
		return nil
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	ext := filepath.Ext(file)
	switch ext {
	case ".json":
		err = json.Unmarshal(data, c)
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, c)
	default:
		err = fmt.Errorf("unsupported config file format: %s", ext)
	}
	if err != nil {
		return err
	}

	c.applyLegacyCompatibility()
	return nil
}

func (c *Config) applyLegacyCompatibility() {
	if strings.TrimSpace(c.SchemaVersion) == "" {
		c.SchemaVersion = defaultSchemaVersion
	}

	if len(c.Listeners) == 0 {
		if listener := legacyListener("http", c.MicroProxy.HTTPProto, c.MicroProxy, true); listener != nil {
			c.Listeners = append(c.Listeners, *listener)
		}
		if listener := legacyListener("https", c.MicroProxy.HTTPSProto, c.MicroProxy, false); listener != nil {
			c.Listeners = append(c.Listeners, *listener)
		}
		if listener := legacyListener("socks5", c.MicroProxy.SOCKS5Proto, c.MicroProxy, false); listener != nil {
			c.Listeners = append(c.Listeners, *listener)
		}
	}

	if len(c.Providers) == 0 {
		for i, proxy := range c.UpstreamProxy.Proxies {
			c.Providers = append(c.Providers, ProviderConfig{
				Name: fmt.Sprintf("legacy-upstream-%d", i),
				Type: "legacy_upstream_proxy",
				Endpoints: []ProviderEndpoint{
					{URL: proxy, Priority: 100, Weight: 1},
				},
				Capabilities: []string{"forward_proxy"},
				Health: ProviderHealthConfig{
					Enabled: false,
				},
			})
		}
	}

	if len(c.Policies) == 0 {
		for i, login := range c.UpstreamProxy.Logins {
			c.Policies = append(c.Policies, PolicyConfig{
				Name:   fmt.Sprintf("legacy-login-%d", i),
				Type:   "auth",
				Action: "upstream_credentials",
				Selectors: map[string]string{
					"ip_range": login.IPRange,
				},
				Parameters: map[string]string{
					"username": login.Username,
					"password": login.Password,
				},
			})
		}
	}
}

func legacyListener(protoType, addr string, cfg ProxyConfig, defaultEnabled bool) *ListenerConfig {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}

	listener := &ListenerConfig{
		Name:      fmt.Sprintf("legacy-%s", protoType),
		Type:      protoType,
		Address:   addr,
		RateLimit: cfg.RateLimit,
		AuthType:  cfg.AuthType,
		Enabled:   defaultEnabled,
	}

	if protoType == "https" {
		listener.TLS = &TLSConfig{CertFile: cfg.CertFile, KeyFile: cfg.KeyFile}
	}

	return listener
}

// Validate ensures configuration is safe to bootstrap.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}

	if strings.TrimSpace(c.SchemaVersion) == "" {
		return fmt.Errorf("schema_version cannot be empty")
	}

	if len(c.Listeners) == 0 {
		return fmt.Errorf("at least one listener must be configured")
	}

	for idx, listener := range c.Listeners {
		if strings.TrimSpace(listener.Type) == "" {
			return fmt.Errorf("listeners[%d].type cannot be empty", idx)
		}
		if strings.TrimSpace(listener.Address) == "" {
			return fmt.Errorf("listeners[%d].address cannot be empty", idx)
		}
		if err := validateAddr(listener.Address, fmt.Sprintf("listeners[%d].address", idx)); err != nil {
			return err
		}
		if listener.Type == "https" {
			if listener.TLS == nil {
				return fmt.Errorf("listeners[%d].tls is required for https listeners", idx)
			}
			if (listener.TLS.CertFile == "") != (listener.TLS.KeyFile == "") {
				return fmt.Errorf("listeners[%d].tls.cert_file and listeners[%d].tls.key_file must both be set", idx, idx)
			}
		}
	}

	for idx, provider := range c.Providers {
		if strings.TrimSpace(provider.Type) == "" {
			return fmt.Errorf("providers[%d].type cannot be empty", idx)
		}
		if len(provider.Endpoints) == 0 {
			return fmt.Errorf("providers[%d].endpoints must contain at least one endpoint", idx)
		}
		for endpointIdx, endpoint := range provider.Endpoints {
			if strings.TrimSpace(endpoint.URL) == "" {
				return fmt.Errorf("providers[%d].endpoints[%d].url cannot be empty", idx, endpointIdx)
			}
			u, err := url.Parse(endpoint.URL)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return fmt.Errorf("providers[%d].endpoints[%d].url must be a valid URL", idx, endpointIdx)
			}
		}
		if provider.Health.IntervalSeconds < 0 || provider.Health.TimeoutSeconds < 0 || provider.Health.FailureThreshold < 0 {
			return fmt.Errorf("providers[%d].health values cannot be negative", idx)
		}
	}

	for idx, rule := range c.UpstreamProxy.Logins {
		if strings.TrimSpace(rule.IPRange) == "" {
			return fmt.Errorf("upstream_proxy.logins[%d].ip_range cannot be empty", idx)
		}
		if _, _, err := net.ParseCIDR(rule.IPRange); err != nil {
			return fmt.Errorf("upstream_proxy.logins[%d].ip_range must be a valid CIDR: %w", idx, err)
		}
	}

	return nil
}

func validateAddr(addr, field string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}

	if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
		return fmt.Errorf("%s must be a valid listen address: %w", field, err)
	}

	return nil
}
