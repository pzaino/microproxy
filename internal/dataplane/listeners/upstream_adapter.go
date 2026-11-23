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

// SessionSnapshot is an immutable pinned sticky-session identity for one
// provider. It is resolved once per operation so concurrent rotation cannot
// mix identities within a single HTTP request or CONNECT tunnel.
type SessionSnapshot struct {
	Provider   string
	SessionID  string
	Generation uint64
}

// SessionSnapshotProvider supplies pinned snapshots for session-enabled
// providers. Implemented by the dataplane SessionManager.
type SessionSnapshotProvider interface {
	Snapshot(provider string) (SessionSnapshot, bool)
}

type sessionSnapshotKey string

const snapshotContextKey sessionSnapshotKey = "session-snapshot"

// WithSessionSnapshot pins a snapshot into the request context.
func WithSessionSnapshot(ctx context.Context, snapshot SessionSnapshot) context.Context {
	return context.WithValue(ctx, snapshotContextKey, snapshot)
}

// SessionSnapshotFromContext returns the pinned snapshot, if any.
func SessionSnapshotFromContext(ctx context.Context) (SessionSnapshot, bool) {
	snapshot, ok := ctx.Value(snapshotContextKey).(SessionSnapshot)
	if !ok || snapshot.Provider == "" || snapshot.SessionID == "" {
		return SessionSnapshot{}, false
	}
	return snapshot, true
}

// UpstreamAdapter abstracts interactions with an upstream provider type.
type UpstreamAdapter interface {
	PrepareRequest(req *http.Request, endpoint *url.URL) (*http.Request, error)
	DialConnect(ctx context.Context, targetAddr string, endpoint *url.URL, dialer *net.Dialer) (net.Conn, error)
	RoundTrip(req *http.Request, endpoint *url.URL, transport *http.Transport, responseHeaderTimeout time.Duration) (*http.Response, error)
	RotateIdentity(ctx context.Context) error
	Capabilities() []string
}
