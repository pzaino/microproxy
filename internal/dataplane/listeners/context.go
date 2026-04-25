package listeners

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

type contextKey string

const metadataContextKey contextKey = "request-metadata"

// RequestMetadata carries per-request values for future routing/observability.
type RequestMetadata struct {
	RequestID    string
	TenantID     string
	Provider     string
	Policy       string
	PolicyAction string
	PolicyReason string
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
