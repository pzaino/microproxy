package listeners

import (
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// rateLimiter is a dependency-free token-bucket rate limiter with a steady rate
// (tokens per second) and a burst equal to the rate. It is safe for concurrent
// use. A limiter with a non-positive rate is disabled and always allows.
//
// One limiter backs one listener (per-listener aggregate limiting), so the first
// `limit` requests within a second are admitted from the bucket, after which the
// rate is enforced at the configured steady rate.
type rateLimiter struct {
	mu      sync.Mutex
	enabled bool
	rate    float64 // tokens per second
	burst   float64 // maximum bucket size
	tokens  float64 // available tokens (0..burst)
	last    time.Time
	now     func() time.Time
}

func newRateLimiter(perSecond int) *rateLimiter {
	if perSecond <= 0 {
		return &rateLimiter{now: time.Now}
	}
	return &rateLimiter{
		enabled: true,
		rate:    float64(perSecond),
		burst:   float64(perSecond),
		tokens:  float64(perSecond),
		now:     time.Now,
	}
}

// allow refills the bucket from the last call and consumes one token when
// available. When a token cannot be consumed it reports false and a
// Retry-After duration (rounded up to a whole second, minimum one second) so
// callers can advise the client how long to wait.
func (l *rateLimiter) allow() (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.enabled {
		return true, 0
	}
	now := l.now()
	if l.last.IsZero() {
		l.last = now
	}
	if elapsed := now.Sub(l.last); elapsed != 0 {
		l.tokens += elapsed.Seconds() * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.last = now
	}
	if l.tokens >= 1 {
		l.tokens--
		return true, 0
	}
	secondsToNext := math.Ceil((1 - l.tokens) / l.rate)
	if secondsToNext < 1 {
		secondsToNext = 1
	}
	return false, time.Duration(secondsToNext) * time.Second
}

// rateLimitMiddleware enforces a per-listener request-rate limit. When the
// limit is non-positive the middleware is a no-op and the wrapped handler is
// returned directly.
type rateLimitMiddleware struct {
	limiter *rateLimiter
	next    http.Handler
}

// NewRateLimitMiddleware wraps next so that at most perSecond requests per
// second (with a burst of perSecond) are forwarded. A non-positive limit
// disables the limitation. Excess requests receive a 429 Too Many Requests
// response with a Retry-After header and a JSON error body; no work is done for
// them.
func NewRateLimitMiddleware(perSecond int, next http.Handler) http.Handler {
	limiter := newRateLimiter(perSecond)
	if !limiter.enabled {
		return next
	}
	return rateLimitMiddleware{limiter: limiter, next: next}
}

func (m rateLimitMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	allowed, retryAfter := m.limiter.allow()
	if !allowed {
		writeTooManyRequests(rw, retryAfter)
		return
	}
	m.next.ServeHTTP(rw, req)
}

func writeTooManyRequests(rw http.ResponseWriter, retryAfter time.Duration) {
	seconds := int64((retryAfter + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	rw.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(rw).Encode(map[string]any{
		"error": map[string]string{
			"code":    "rate_limited",
			"message": "request rate exceeds the listener's configured limit",
		},
	})
}

// PerConnGate is a per-listener aggregate gate for non-HTTP listener types (for
// example SOCKS5) where there is no HTTP status response to return to a
// rate-limited peer. A non-positive rate disables the gate (always allows). A
// denied connection is closed by the caller.
type PerConnGate struct {
	limiter *rateLimiter
}

// NewPerConnGate returns a gate allowing at most perSecond connection accepts per
// second with a burst of perSecond. A non-positive limit disables the gate.
func NewPerConnGate(perSecond int) *PerConnGate {
	return &PerConnGate{limiter: newRateLimiter(perSecond)}
}

// Allow reports whether another connection accept may proceed now, consuming one
// token when allowed. When the gate is disabled it always reports true.
func (g *PerConnGate) Allow() bool {
	allowed, _ := g.limiter.allow()
	return allowed
}
