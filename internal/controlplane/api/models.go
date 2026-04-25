package api

import (
	"strings"
	"time"

	"github.com/pzaino/microproxy/pkg/config"
)

// HealthResponse is returned by /api/v1/health.
type HealthResponse struct {
	Status    string    `json:"status"`
	Service   string    `json:"service"`
	Timestamp time.Time `json:"timestamp"`
}

// ConfigResponse wraps the read-only runtime config.
type ConfigResponse struct {
	Config any `json:"config"`
}

// ErrorEnvelope defines the common API error payload.
type ErrorEnvelope struct {
	Error ErrorModel `json:"error"`
}

// ErrorModel defines API error details.
type ErrorModel struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// StubListResponse is used by unimplemented collection resources.
type StubListResponse struct {
	Resource string `json:"resource"`
	Items    []any  `json:"items"`
}

type Provider struct {
	ID              string       `json:"id"`
	ResourceVersion string       `json:"resourceVersion"`
	Spec            ProviderSpec `json:"spec"`
}

type ProviderSpec struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
}

type ProviderWriteRequest struct {
	ResourceVersion string       `json:"resourceVersion,omitempty"`
	Provider        ProviderSpec `json:"provider"`
}

type ProviderPatchRequest struct {
	ResourceVersion string         `json:"resourceVersion,omitempty"`
	Patch           map[string]any `json:"patch"`
}

type ProviderResponse struct {
	Provider Provider `json:"provider"`
}

type ProviderListResponse struct {
	Items []Provider `json:"items"`
}

const redactedSecretValue = "[REDACTED]"

// NewSanitizedConfigView returns a copy of cfg with secrets masked.
func NewSanitizedConfigView(cfg *config.Config) *config.Config {
	if cfg == nil {
		return config.NewConfig()
	}

	sanitized := *cfg
	sanitized.Providers = make([]config.ProviderConfig, len(cfg.Providers))
	for i, provider := range cfg.Providers {
		sanitizedProvider := provider
		sanitizedProvider.Auth = sanitizeProviderAuth(provider.Auth)
		sanitized.Providers[i] = sanitizedProvider
	}

	return &sanitized
}

func sanitizeProviderAuth(auth config.ProviderAuthConfig) config.ProviderAuthConfig {
	sanitized := auth

	if strings.TrimSpace(sanitized.Password) != "" {
		sanitized.Password = redactedSecretValue
	}
	if strings.TrimSpace(sanitized.Token) != "" {
		sanitized.Token = redactedSecretValue
	}

	if len(sanitized.Headers) == 0 {
		return sanitized
	}

	headers := make(map[string]string, len(sanitized.Headers))
	for key, value := range sanitized.Headers {
		if isSensitiveAuthHeader(key) && strings.TrimSpace(value) != "" {
			headers[key] = redactedSecretValue
			continue
		}
		headers[key] = value
	}
	sanitized.Headers = headers

	return sanitized
}

func isSensitiveAuthHeader(header string) bool {
	h := strings.ToLower(strings.TrimSpace(header))
	return strings.Contains(h, "authorization") ||
		strings.Contains(h, "api-key") ||
		strings.Contains(h, "apikey") ||
		strings.Contains(h, "token") ||
		strings.Contains(h, "secret") ||
		strings.Contains(h, "password")
}
