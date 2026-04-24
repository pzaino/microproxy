package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync/atomic"
	"time"
)

const requestIDHeader = "X-Request-ID"

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
