package config

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
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
	return c, err
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
