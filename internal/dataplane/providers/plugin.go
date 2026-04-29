package providers

import (
	"context"
	"net"
	"net/http"

	"github.com/pzaino/microproxy/pkg/config"
)

type DialPlan struct {
	Network string
	Address string
}

type RotateResult struct{ SessionID string }

type StatusSnapshot struct {
	State  string
	Reason string
}

type Plugin interface {
	ValidateConfig(provider config.ProviderConfig) error
	ResolveEndpoint(ctx context.Context, provider config.ProviderConfig, hint map[string]string) (config.ProviderEndpoint, error)
	PrepareRequest(ctx context.Context, provider config.ProviderConfig, req *http.Request) error
	Dial(ctx context.Context, provider config.ProviderConfig, endpoint config.ProviderEndpoint) (net.Conn, error)
	Rotate(ctx context.Context, provider config.ProviderConfig, sessionID string) (RotateResult, error)
	FetchStatus(ctx context.Context, provider config.ProviderConfig) (StatusSnapshot, error)
}
