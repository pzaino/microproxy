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

// Config holds the configuration for the proxy server
type Config struct {
	MicroProxy    ProxyConfig         `json:"microproxy" yaml:"microproxy"`
	UpstreamProxy UpstreamProxyConfig `json:"upstream_proxy" yaml:"upstream_proxy"`
}

// ProxyConfig holds the configuration for the proxy server
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

// NewConfig returns a new Config instance
func NewConfig() *Config {
	return &Config{
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

// LoadConfig loads the configuration from the given file
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

// Load loads the configuration from the given file
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
	return err
}

// Validate ensures configuration is safe to bootstrap.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}

	if strings.TrimSpace(c.MicroProxy.HTTPProto) == "" &&
		strings.TrimSpace(c.MicroProxy.HTTPSProto) == "" &&
		strings.TrimSpace(c.MicroProxy.SOCKS5Proto) == "" {
		return fmt.Errorf("at least one listener (http, https, or socks5) must be configured")
	}

	if err := validateAddr(c.MicroProxy.HTTPProto, "microproxy.http_proto"); err != nil {
		return err
	}
	if err := validateAddr(c.MicroProxy.HTTPSProto, "microproxy.https_proto"); err != nil {
		return err
	}
	if err := validateAddr(c.MicroProxy.SOCKS5Proto, "microproxy.socks5_proto"); err != nil {
		return err
	}

	if (c.MicroProxy.CertFile == "") != (c.MicroProxy.KeyFile == "") {
		return fmt.Errorf("microproxy.cert_file and microproxy.key_file must both be set for tls")
	}

	for idx, proxy := range c.UpstreamProxy.Proxies {
		if strings.TrimSpace(proxy) == "" {
			return fmt.Errorf("upstream_proxy.proxies[%d] cannot be empty", idx)
		}
		u, err := url.Parse(proxy)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("upstream_proxy.proxies[%d] must be a valid URL", idx)
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
