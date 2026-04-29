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
	developmentModeEnv     = "MICROPROXY_DEVELOPMENT_MODE"
	startupModeEnv         = "MICROPROXY_STARTUP_MODE"
	profileEnv             = "MICROPROXY_PROFILE"
	defaultControlAPIKey   = "microproxy-controlplane-dev-key"
)

type contextKey string

const requestIDContextKey contextKey = "request_id"
const actorContextKey contextKey = "actor"

type role string

const (
	roleObserver role = "observer"
	roleOperator role = "operator"
	roleAdmin    role = "admin"
)

type actorIdentity struct {
	Kind string
	ID   string
	Role role
}

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

func newAuthMiddleware() (func(http.Handler) http.Handler, error) {
	authenticator, err := newAuthenticator()
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
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
	}, nil
}

type requestAuthenticator struct {
	apiKeys map[string]actorIdentity
	jwts    map[string]actorIdentity
}

func newAuthenticator() (requestAuthenticator, error) {
	apiKeys := parseCredentialSetWithRoles(os.Getenv(controlPlaneAPIKeysEnv), "api_key")
	jwts := parseCredentialSetWithRoles(os.Getenv(controlPlaneJWTsEnv), "jwt")
	developmentMode := parseDevelopmentMode(os.Getenv(developmentModeEnv))
	if developmentMode && (isProductionMode(os.Getenv(startupModeEnv)) || isProductionMode(os.Getenv(profileEnv))) {
		return requestAuthenticator{}, fmt.Errorf("invalid control-plane auth configuration: %s cannot be enabled when %s or %s is production", developmentModeEnv, startupModeEnv, profileEnv)
	}

	if len(apiKeys) == 0 && len(jwts) == 0 && !developmentMode {
		return requestAuthenticator{}, fmt.Errorf(
			"invalid control-plane auth configuration: set %s or %s (or explicitly enable %s for development only)",
			controlPlaneAPIKeysEnv,
			controlPlaneJWTsEnv,
			developmentModeEnv,
		)
	}

	if len(apiKeys) == 0 && developmentMode {
		apiKeys[defaultControlAPIKey] = actorIdentity{Kind: "api_key", ID: defaultControlAPIKey, Role: roleAdmin}
	}

	return requestAuthenticator{
		apiKeys: apiKeys,
		jwts:    jwts,
	}, nil
}

func parseCredentialSetWithRoles(raw, kind string) map[string]actorIdentity {
	values := make(map[string]actorIdentity)
	for _, entry := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		credential := trimmed
		assignedRole := roleAdmin
		if parts := strings.SplitN(trimmed, "=", 2); len(parts) == 2 {
			credential = strings.TrimSpace(parts[0])
			assignedRole = parseRole(parts[1])
		}
		if credential == "" {
			continue
		}
		values[credential] = actorIdentity{Kind: kind, ID: credential, Role: assignedRole}
	}
	return values
}

func parseRole(raw string) role {
	switch role(strings.ToLower(strings.TrimSpace(raw))) {
	case roleObserver, roleOperator, roleAdmin:
		return role(strings.ToLower(strings.TrimSpace(raw)))
	default:
		return roleAdmin
	}
}

func isProductionMode(raw string) bool { return strings.EqualFold(strings.TrimSpace(raw), "production") }

func parseDevelopmentMode(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
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
		if actor, ok := a.apiKeys[apiKey]; ok {
			req.Header.Set("X-Actor-Role", string(actor.Role))
			req.Header.Set("X-Actor-ID", actor.ID)
			req.Header.Set("X-Actor-Kind", actor.Kind)
			return true, 0, "", ""
		}
	}
	if jwt != "" {
		if actor, ok := a.jwts[jwt]; ok {
			req.Header.Set("X-Actor-Role", string(actor.Role))
			req.Header.Set("X-Actor-ID", actor.ID)
			req.Header.Set("X-Actor-Kind", actor.Kind)
			return true, 0, "", ""
		}
	}

	return false, http.StatusForbidden, "forbidden", "invalid authentication credentials"
}

func roleAuthorizeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if !strings.HasPrefix(req.URL.Path, "/api/v1/") || req.URL.Path == "/api/v1/health" {
			next.ServeHTTP(rw, req)
			return
		}
		role := parseRole(req.Header.Get("X-Actor-Role"))
		if !isRoleAllowed(role, req.Method, req.URL.Path) {
			writeError(rw, http.StatusForbidden, "forbidden", "insufficient role permissions", requestIDFromRequest(req))
			return
		}
		ctx := context.WithValue(req.Context(), actorContextKey, actorIdentity{Kind: req.Header.Get("X-Actor-Kind"), ID: req.Header.Get("X-Actor-ID"), Role: role})
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

func isRoleAllowed(r role, method, path string) bool {
	if method == http.MethodGet {
		return true
	}
	if r == roleAdmin {
		return true
	}
	if r == roleOperator {
		return path == "/api/v1/providers" || strings.HasPrefix(path, "/api/v1/providers/")
	}
	return false
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
