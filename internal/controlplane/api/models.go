package api

import "time"

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
