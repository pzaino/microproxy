package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"
)

const (
	requestIDHeader = "X-Request-ID"
	apiKeyHeader    = "X-API-Key"
)

const (
	controlPlaneAPIKeysEnv = "MICROPROXY_CONTROLPLANE_API_KEYS"
	controlPlaneJWTsEnv    = "MICROPROXY_CONTROLPLANE_JWTS"
	defaultControlAPIKey   = "microproxy-controlplane-dev-key"
)

type contextKey string

const requestIDContextKey contextKey = "request_id"

var requestCounter uint64

func nextRequestID() string {
	seq := atomic.AddUint64(&requestCounter, 1)
	return fmt.Sprintf("cp-%d", seq)
}

func requestIDFromRequest(req *http.Request) string {
	if req == nil {
		return ""
	}
	if requestID, ok := req.Context().Value(requestIDContextKey).(string); ok {
		return requestID
	}
	return ""
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		requestID := req.Header.Get(requestIDHeader)
		if requestID == "" {
			requestID = nextRequestID()
		}
		rw.Header().Set(requestIDHeader, requestID)
		req = req.WithContext(context.WithValue(req.Context(), requestIDContextKey, requestID))
		next.ServeHTTP(rw, req)
	})
}

func panicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				reqID := requestIDFromRequest(req)
				slog.Error("control-plane panic recovered",
					"request_id", reqID,
					"method", req.Method,
					"path", req.URL.Path,
					"panic", rec,
					"stack", string(debug.Stack()),
				)
				writeError(rw, http.StatusInternalServerError, "internal_error", "internal server error", reqID)
			}
		}()
		next.ServeHTTP(rw, req)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: rw, statusCode: http.StatusOK}
		next.ServeHTTP(recorder, req)
		slog.Info("control-plane request",
			"request_id", requestIDFromRequest(req),
			"method", req.Method,
			"path", req.URL.Path,
			"status", recorder.statusCode,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

func authMiddleware(next http.Handler) http.Handler {
	authenticator := newAuthenticator()
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/v1/health" {
			next.ServeHTTP(rw, req)
			return
		}
		if !strings.HasPrefix(req.URL.Path, "/api/v1/") {
			next.ServeHTTP(rw, req)
			return
		}

		allowed, status, code, message := authenticator.authorize(req)
		if !allowed {
			writeError(rw, status, code, message, requestIDFromRequest(req))
			return
		}
		next.ServeHTTP(rw, req)
	})
}

type requestAuthenticator struct {
	apiKeys map[string]struct{}
	jwts    map[string]struct{}
}

func newAuthenticator() requestAuthenticator {
	apiKeys := parseCredentialSet(os.Getenv(controlPlaneAPIKeysEnv))
	if len(apiKeys) == 0 {
		apiKeys[defaultControlAPIKey] = struct{}{}
	}

	return requestAuthenticator{
		apiKeys: apiKeys,
		jwts:    parseCredentialSet(os.Getenv(controlPlaneJWTsEnv)),
	}
}

func parseCredentialSet(raw string) map[string]struct{} {
	values := make(map[string]struct{})
	for _, entry := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		values[trimmed] = struct{}{}
	}
	return values
}

func (a requestAuthenticator) authorize(req *http.Request) (bool, int, string, string) {
	apiKey := strings.TrimSpace(req.Header.Get(apiKeyHeader))
	jwt, jwtStatus, jwtCode, jwtMsg := extractBearerToken(req.Header.Get("Authorization"))
	if jwtStatus != 0 {
		return false, jwtStatus, jwtCode, jwtMsg
	}

	if apiKey == "" && jwt == "" {
		return false, http.StatusUnauthorized, "unauthorized", "missing authentication credentials"
	}

	if apiKey != "" {
		if _, ok := a.apiKeys[apiKey]; ok {
			return true, 0, "", ""
		}
	}
	if jwt != "" {
		if _, ok := a.jwts[jwt]; ok {
			return true, 0, "", ""
		}
	}

	return false, http.StatusForbidden, "forbidden", "invalid authentication credentials"
}

func extractBearerToken(authorization string) (token string, status int, code, message string) {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return "", 0, "", ""
	}
	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", http.StatusUnauthorized, "unauthorized", "authorization header must use bearer scheme"
	}
	if strings.TrimSpace(parts[1]) == "" {
		return "", http.StatusUnauthorized, "unauthorized", "authorization token is empty"
	}
	return parts[1], 0, "", ""
}

func chain(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	wrapped := handler
	for i := len(middlewares) - 1; i >= 0; i-- {
		wrapped = middlewares[i](wrapped)
	}
	return wrapped
}

// statusRecorder tracks response status for logs.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}
