package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

const defaultSchemaVersion = "1"

const (
	sessionIDPrefix      = "session-"
	sessionIDEntropyByte = 16
)

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
	PolicyEngine  PolicyEngineConfig  `json:"policy_engine,omitempty" yaml:"policy_engine,omitempty"`
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
	Username  string     `json:"username,omitempty" yaml:"username,omitempty"`
	Password  string     `json:"password,omitempty" yaml:"password,omitempty"`
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

type PolicyEngineConfig struct {
	ChainMode string             `json:"chain_mode,omitempty" yaml:"chain_mode,omitempty"`
	SafeMode  PolicySafeModeFlag `json:"safe_mode,omitempty" yaml:"safe_mode,omitempty"`
}

type PolicySafeModeFlag struct {
	AllowBodyMutation bool `json:"allow_body_mutation" yaml:"allow_body_mutation"`
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
	StartupAddress   string `json:"startup_address,omitempty" yaml:"startup_address,omitempty"`
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

type FieldValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e FieldValidationError) Error() string {
	if strings.TrimSpace(e.Field) == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

type ValidationErrors struct {
	Errors []FieldValidationError `json:"errors"`
}

func (e *ValidationErrors) Error() string {
	if e == nil || len(e.Errors) == 0 {
		return ""
	}

	parts := make([]string, 0, len(e.Errors))
	for _, fieldErr := range e.Errors {
		parts = append(parts, fieldErr.Error())
	}
	return strings.Join(parts, "; ")
}

func (e *ValidationErrors) Add(field, message string) {
	if strings.TrimSpace(message) == "" {
		return
	}
	e.Errors = append(e.Errors, FieldValidationError{Field: field, Message: message})
}

func (e *ValidationErrors) Merge(other *ValidationErrors) {
	if e == nil || other == nil || len(other.Errors) == 0 {
		return
	}
	e.Errors = append(e.Errors, other.Errors...)
}

func (e *ValidationErrors) OrNil() error {
	if e == nil || len(e.Errors) == 0 {
		return nil
	}
	return e
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

// generateSessionID returns a URL-safe session identifier for ${SESSION_ID} substitution.
//
// Format guarantees:
//   - Always prefixed with "session-".
//   - Random segment is base64.RawURLEncoding (characters [A-Za-z0-9_-], no padding).
//
// Entropy guarantee:
//   - Uses 16 bytes from crypto/rand (128 bits of entropy) for the random segment.
func generateSessionID() string {
	b := make([]byte, sessionIDEntropyByte)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("generate session id: %w", err))
	}

	return sessionIDPrefix + base64.RawURLEncoding.EncodeToString(b)
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
	if err := c.Load(file); err != nil {
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
	errs := &ValidationErrors{}

	if c == nil {
		errs.Add("config", "is nil")
		return errs
	}

	if strings.TrimSpace(c.SchemaVersion) == "" {
		errs.Add("schema_version", "cannot be empty")
	}

	if len(c.Listeners) == 0 {
		errs.Add("listeners", "at least one listener must be configured")
	}

	listenerNameSeen := map[string]int{}
	for idx, listener := range c.Listeners {
		errs.Merge(listener.Validate(fmt.Sprintf("listeners[%d]", idx)))
		if name := strings.TrimSpace(listener.Name); name != "" {
			if seenIdx, exists := listenerNameSeen[name]; exists {
				errs.Add(fmt.Sprintf("listeners[%d].name", idx), fmt.Sprintf("duplicates listeners[%d].name", seenIdx))
			}
			listenerNameSeen[name] = idx
		}
	}

	providerNameSeen := map[string]int{}
	for idx, provider := range c.Providers {
		errs.Merge(provider.Validate(fmt.Sprintf("providers[%d]", idx)))
		if name := strings.TrimSpace(provider.Name); name != "" {
			if seenIdx, exists := providerNameSeen[name]; exists {
				errs.Add(fmt.Sprintf("providers[%d].name", idx), fmt.Sprintf("duplicates providers[%d].name", seenIdx))
			}
			providerNameSeen[name] = idx
		}
	}

	policyNameSeen := map[string]int{}
	for idx, policy := range c.Policies {
		errs.Merge(policy.Validate(fmt.Sprintf("policies[%d]", idx)))
		if name := strings.TrimSpace(policy.Name); name != "" {
			if seenIdx, exists := policyNameSeen[name]; exists {
				errs.Add(fmt.Sprintf("policies[%d].name", idx), fmt.Sprintf("duplicates policies[%d].name", seenIdx))
			}
			policyNameSeen[name] = idx
		}
	}

	tenantIDSeen := map[string]int{}
	for idx, tenant := range c.Tenants {
		errs.Merge(tenant.Validate(fmt.Sprintf("tenants[%d]", idx)))
		if id := strings.TrimSpace(tenant.ID); id != "" {
			if seenIdx, exists := tenantIDSeen[id]; exists {
				errs.Add(fmt.Sprintf("tenants[%d].id", idx), fmt.Sprintf("duplicates tenants[%d].id", seenIdx))
			}
			tenantIDSeen[id] = idx
		}
	}

	errs.Merge(c.Routing.Validate("routing", providerNameSeen, policyNameSeen))
	errs.Merge(c.PolicyEngine.Validate("policy_engine"))
	errs.Merge(c.UpstreamProxy.Validate("upstream_proxy"))

	return errs.OrNil()
}

func (l ListenerConfig) Validate(fieldPath string) *ValidationErrors {
	errs := &ValidationErrors{}

	if strings.TrimSpace(l.Name) == "" {
		errs.Add(fieldPath+".name", "cannot be empty")
	}

	proto := strings.ToLower(strings.TrimSpace(l.Type))
	switch proto {
	case "http", "https", "socks5":
	default:
		errs.Add(fieldPath+".type", "must be one of: http, https, socks5")
	}

	if strings.TrimSpace(l.Address) == "" {
		errs.Add(fieldPath+".address", "cannot be empty")
	} else if err := validateAddr(l.Address, fieldPath+".address"); err != nil {
		errs.Add(fieldPath+".address", err.Error())
	}

	if proto == "https" {
		if l.TLS == nil {
			errs.Add(fieldPath+".tls", "is required for https listeners")
		} else {
			errs.Merge(l.TLS.Validate(fieldPath + ".tls"))
		}
	} else if l.TLS != nil {
		errs.Add(fieldPath+".tls", "must only be set for https listeners")
	}

	switch strings.ToLower(strings.TrimSpace(l.AuthType)) {
	case "", "none":
	case "basic":
		if strings.TrimSpace(l.Username) == "" {
			errs.Add(fieldPath+".username", "is required for basic auth")
		}
		if strings.TrimSpace(l.Password) == "" {
			errs.Add(fieldPath+".password", "is required for basic auth")
		}
	default:
		errs.Add(fieldPath+".auth_type", "must be one of: none, basic")
	}

	return errs
}

func (t *TLSConfig) Validate(fieldPath string) *ValidationErrors {
	errs := &ValidationErrors{}

	if t == nil {
		errs.Add(fieldPath, "cannot be nil")
		return errs
	}

	certSet := strings.TrimSpace(t.CertFile) != ""
	keySet := strings.TrimSpace(t.KeyFile) != ""
	if certSet != keySet {
		errs.Add(fieldPath, "cert_file and key_file must both be set")
	}

	return errs
}

func (p ProviderConfig) Validate(fieldPath string) *ValidationErrors {
	errs := &ValidationErrors{}

	if strings.TrimSpace(p.Name) == "" {
		errs.Add(fieldPath+".name", "cannot be empty")
	}
	if strings.TrimSpace(p.Type) == "" {
		errs.Add(fieldPath+".type", "cannot be empty")
	}
	if len(p.Endpoints) == 0 {
		errs.Add(fieldPath+".endpoints", "must contain at least one endpoint")
	}

	for idx, endpoint := range p.Endpoints {
		errs.Merge(endpoint.Validate(fmt.Sprintf("%s.endpoints[%d]", fieldPath, idx)))
	}

	errs.Merge(p.Auth.Validate(fieldPath + ".auth"))
	errs.Merge(p.Health.Validate(fieldPath + ".health"))
	return errs
}

func (a ProviderAuthConfig) Validate(fieldPath string) *ValidationErrors {
	errs := &ValidationErrors{}

	switch strings.ToLower(strings.TrimSpace(a.Type)) {
	case "", "none":
		return errs
	case "basic":
		if strings.TrimSpace(a.Username) == "" {
			errs.Add(fieldPath+".username", "is required for basic auth")
		}
		if strings.TrimSpace(a.Password) == "" {
			errs.Add(fieldPath+".password", "is required for basic auth")
		}
	case "bearer":
		if strings.TrimSpace(a.Token) == "" {
			errs.Add(fieldPath+".token", "is required for bearer auth")
		}
	case "api_key":
		if len(a.Headers) == 0 {
			errs.Add(fieldPath+".headers", "must contain at least one header for api_key auth")
		}
	default:
		errs.Add(fieldPath+".type", "must be one of: none, basic, bearer, api_key")
	}

	return errs
}

func (e ProviderEndpoint) Validate(fieldPath string) *ValidationErrors {
	errs := &ValidationErrors{}

	if strings.TrimSpace(e.URL) == "" {
		errs.Add(fieldPath+".url", "cannot be empty")
	} else {
		parsed, err := url.Parse(e.URL)
		if err != nil || strings.TrimSpace(parsed.Scheme) == "" || strings.TrimSpace(parsed.Host) == "" {
			errs.Add(fieldPath+".url", "must be a valid URL with scheme and host")
		}
	}

	if e.Priority < 0 {
		errs.Add(fieldPath+".priority", "cannot be negative")
	}
	if e.Weight < 0 {
		errs.Add(fieldPath+".weight", "cannot be negative")
	}

	return errs
}

func (h ProviderHealthConfig) Validate(fieldPath string) *ValidationErrors {
	errs := &ValidationErrors{}

	if h.IntervalSeconds < 0 {
		errs.Add(fieldPath+".interval_seconds", "cannot be negative")
	}
	if h.TimeoutSeconds < 0 {
		errs.Add(fieldPath+".timeout_seconds", "cannot be negative")
	}
	if h.FailureThreshold < 0 {
		errs.Add(fieldPath+".failure_threshold", "cannot be negative")
	}

	return errs
}

func (r RoutingConfig) Validate(fieldPath string, providerNames map[string]int, policyNames map[string]int) *ValidationErrors {
	errs := &ValidationErrors{}

	if p := strings.TrimSpace(r.DefaultProvider); p != "" {
		if _, ok := providerNames[p]; !ok {
			errs.Add(fieldPath+".default_provider", "must reference an existing provider name")
		}
	}

	ruleNameSeen := map[string]int{}
	for idx, rule := range r.Rules {
		rulePath := fmt.Sprintf("%s.rules[%d]", fieldPath, idx)
		errs.Merge(rule.Validate(rulePath, providerNames, policyNames))
		if name := strings.TrimSpace(rule.Name); name != "" {
			if seenIdx, exists := ruleNameSeen[name]; exists {
				errs.Add(rulePath+".name", fmt.Sprintf("duplicates %s.rules[%d].name", fieldPath, seenIdx))
			}
			ruleNameSeen[name] = idx
		}
	}

	return errs
}

func (r RoutingRule) Validate(fieldPath string, providerNames map[string]int, policyNames map[string]int) *ValidationErrors {
	errs := &ValidationErrors{}

	if strings.TrimSpace(r.Name) == "" {
		errs.Add(fieldPath+".name", "cannot be empty")
	}
	if p := strings.TrimSpace(r.Provider); p == "" {
		errs.Add(fieldPath+".provider", "cannot be empty")
	} else if _, ok := providerNames[p]; !ok {
		errs.Add(fieldPath+".provider", "must reference an existing provider name")
	}
	if policy := strings.TrimSpace(r.PolicyRef); policy != "" {
		if _, ok := policyNames[policy]; !ok {
			errs.Add(fieldPath+".policy_ref", "must reference an existing policy name")
		}
	}

	for key, value := range r.Match {
		if strings.Contains(strings.ToLower(key), "cidr") || strings.HasSuffix(strings.ToLower(key), "ip_range") {
			if _, _, err := net.ParseCIDR(value); err != nil {
				errs.Add(fieldPath+".match."+key, "must be a valid CIDR")
			}
		}
	}

	return errs
}

func (p PolicyConfig) Validate(fieldPath string) *ValidationErrors {
	errs := &ValidationErrors{}

	if strings.TrimSpace(p.Name) == "" {
		errs.Add(fieldPath+".name", "cannot be empty")
	}
	if strings.TrimSpace(p.Type) == "" {
		errs.Add(fieldPath+".type", "cannot be empty")
	}
	if strings.TrimSpace(p.Action) == "" {
		errs.Add(fieldPath+".action", "cannot be empty")
	}
	if ipRange, ok := p.Selectors["ip_range"]; ok {
		if _, _, err := net.ParseCIDR(ipRange); err != nil {
			errs.Add(fieldPath+".selectors.ip_range", "must be a valid CIDR")
		}
	}
	if action := strings.ToLower(strings.TrimSpace(p.Action)); action != "" {
		switch action {
		case "allow", "deny", "route_override", "headers_patch", "redirect", "rewrite", "response_headers_patch", "body_mutation_hook":
		default:
			errs.Add(fieldPath+".action", "must be one of: allow, deny, route_override, headers_patch, redirect, rewrite, response_headers_patch, body_mutation_hook")
		}
	}
	for key, value := range p.Selectors {
		selectorPath := fieldPath + ".selectors." + key
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "url_regex", "domain_suffix_regex", "content_type_regex":
			if _, err := regexp.Compile(value); err != nil {
				errs.Add(selectorPath, "must be a valid regex")
			}
		case "request_size_min", "request_size_max", "response_size_min", "response_size_max":
			if _, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err != nil {
				errs.Add(selectorPath, "must be an integer byte size")
			}
		case "time_window_utc":
			if err := validateTimeWindow(strings.TrimSpace(value)); err != nil {
				errs.Add(selectorPath, err.Error())
			}
		}
	}
	if strings.TrimSpace(p.Parameters["deny_category"]) != "" {
		switch strings.ToLower(strings.TrimSpace(p.Parameters["deny_category"])) {
		case "security", "compliance", "quota", "routing", "content", "other":
		default:
			errs.Add(fieldPath+".parameters.deny_category", "must be one of: security, compliance, quota, routing, content, other")
		}
	}

	return errs
}

func (c PolicyEngineConfig) Validate(fieldPath string) *ValidationErrors {
	errs := &ValidationErrors{}
	switch strings.ToLower(strings.TrimSpace(c.ChainMode)) {
	case "", "stop", "continue":
	default:
		errs.Add(fieldPath+".chain_mode", "must be one of: stop, continue")
	}
	return errs
}

func validateTimeWindow(value string) error {
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return fmt.Errorf("must be in HH:MM-HH:MM format")
	}
	for _, part := range parts {
		if _, err := time.Parse("15:04", strings.TrimSpace(part)); err != nil {
			return fmt.Errorf("must be in HH:MM-HH:MM format")
		}
	}
	return nil
}

func (t TenantConfig) Validate(fieldPath string) *ValidationErrors {
	errs := &ValidationErrors{}
	if strings.TrimSpace(t.Name) == "" {
		errs.Add(fieldPath+".name", "cannot be empty")
	}
	if strings.TrimSpace(t.ID) == "" {
		errs.Add(fieldPath+".id", "cannot be empty")
	}
	return errs
}

func (u UpstreamProxyConfig) Validate(fieldPath string) *ValidationErrors {
	errs := &ValidationErrors{}
	for idx, rule := range u.Logins {
		errs.Merge(rule.Validate(fmt.Sprintf("%s.logins[%d]", fieldPath, idx)))
	}
	return errs
}

func (r LoginRule) Validate(fieldPath string) *ValidationErrors {
	errs := &ValidationErrors{}
	if strings.TrimSpace(r.IPRange) == "" {
		errs.Add(fieldPath+".ip_range", "cannot be empty")
	} else if _, _, err := net.ParseCIDR(r.IPRange); err != nil {
		errs.Add(fieldPath+".ip_range", "must be a valid CIDR")
	}
	return errs
}

func validateAddr(addr, field string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}

	if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
		return fmt.Errorf("%s must be a valid listen address", field)
	}

	return nil
}
