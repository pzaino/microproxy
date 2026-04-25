package listeners

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

var ErrRotateIdentityUnsupported = errors.New("rotate identity not supported")

// UpstreamAdapter abstracts interactions with an upstream provider type.
type UpstreamAdapter interface {
	PrepareRequest(req *http.Request, endpoint *url.URL) (*http.Request, error)
	DialConnect(ctx context.Context, targetAddr string, endpoint *url.URL, dialer *net.Dialer) (net.Conn, error)
	RoundTrip(req *http.Request, endpoint *url.URL, transport *http.Transport, responseHeaderTimeout time.Duration) (*http.Response, error)
	RotateIdentity(ctx context.Context) error
	Capabilities() []string
}
