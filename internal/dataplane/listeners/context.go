package listeners

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

type contextKey string

const metadataContextKey contextKey = "request-metadata"

// RequestMetadata carries per-request values for future routing/observability.
// ListenerName/Provider are trusted values injected from the listening server
// itself. TenantID/Provider initially come from downstream headers and are
// untrusted until a hard listener binding overrides Provider.
type RequestMetadata struct {
	RequestID       string
	TenantID        string
	Provider        string
	Policy          string
	PolicyAction    string
	PolicyReason    string
	PolicyCategory  string
	PolicyTrace     []string
	ContentType     string
	RequestSize     int64
	ResponseSize    int64
	EvaluationClock time.Time
	// ListenerName is the trusted accepting listener name (empty if unknown).
	ListenerName string
	// ListenerProvider is the trusted hard binding for the accepting listener.
	// Empty means legacy routing (no mandatory egress constraint).
	ListenerProvider string
}

type metadataRef struct {
	metadata RequestMetadata
}

func WithMetadata(ctx context.Context, metadata RequestMetadata) context.Context {
	return context.WithValue(ctx, metadataContextKey, &metadataRef{metadata: metadata})
}

func MetadataFromContext(ctx context.Context) (RequestMetadata, bool) {
	switch metadata := ctx.Value(metadataContextKey).(type) {
	case RequestMetadata:
		return metadata, true
	case *metadataRef:
		if metadata == nil {
			return RequestMetadata{}, false
		}
		return metadata.metadata, true
	default:
		return RequestMetadata{}, false
	}
}

func UpdateMetadata(ctx context.Context, fn func(metadata *RequestMetadata)) bool {
	if fn == nil {
		return false
	}
	metadata, ok := ctx.Value(metadataContextKey).(*metadataRef)
	if !ok || metadata == nil {
		return false
	}
	fn(&metadata.metadata)
	return true
}

// MetadataMiddleware injects request metadata and forwards it via request context.
func MetadataMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		metadata := RequestMetadata{
			RequestID: requestIDFromRequest(req),
			TenantID:  req.Header.Get("X-Tenant-ID"),
			Provider:  req.Header.Get("X-Provider-ID"),
		}
		next.ServeHTTP(rw, req.WithContext(WithMetadata(req.Context(), metadata)))
	})
}

// ListenerBindingMiddleware injects the trusted listener identity/binding
// from the accepting server itself, not client headers. When provider is
// non-empty it hard-overrides any client-supplied X-Provider-ID so header
// spoofing cannot escape the binding.
func ListenerBindingMiddleware(listenerName, provider string, next http.Handler) http.Handler {
	if next == nil {
		next = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		if _, ok := MetadataFromContext(ctx); !ok {
			ctx = WithMetadata(ctx, RequestMetadata{RequestID: requestIDFromRequest(req)})
		}
		UpdateMetadata(ctx, func(metadata *RequestMetadata) {
			metadata.ListenerName = listenerName
			metadata.ListenerProvider = provider
			if provider != "" {
				metadata.Provider = provider
			}
		})
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

// ListenerBindingFromContext returns the trusted listener name/binding.
func ListenerBindingFromContext(ctx context.Context) (name, provider string, ok bool) {
	metadata, found := MetadataFromContext(ctx)
	if !found {
		return "", "", false
	}
	if metadata.ListenerName == "" && metadata.ListenerProvider == "" {
		return "", "", false
	}
	return metadata.ListenerName, metadata.ListenerProvider, true
}

// RequiresUpstream reports whether egress must use an explicit upstream
// provider (fail closed) rather than legacy direct fallback. A hard listener
// binding always requires upstream; otherwise any resolved provider name
// requires upstream.
func RequiresUpstream(ctx context.Context, provider string) bool {
	if metadata, ok := MetadataFromContext(ctx); ok {
		if metadata.ListenerProvider != "" {
			return true
		}
	}
	return provider != ""
}

func requestIDFromRequest(req *http.Request) string {
	if existing := req.Header.Get("X-Request-ID"); existing != "" {
		return existing
	}

	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "req-unknown"
	}

	return "req-" + hex.EncodeToString(random[:])
}
