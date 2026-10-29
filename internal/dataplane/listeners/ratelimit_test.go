package listeners

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimiter_DisabledAllowsAll(t *testing.T) {
	limiter := newRateLimiter(0)
	for i := 0; i < 100; i++ {
		if allowed, _ := limiter.allow(); !allowed {
			t.Fatalf("disabled limiter must always allow (iteration %d)", i)
		}
	}

	// A nil limiter is also a permissive no-op.
	var nilLimiter *rateLimiter
	if allowed, retry := nilLimiter.allow(); !allowed || retry != 0 {
		t.Fatalf("nil limiter must allow, got allowed=%v retry=%v", allowed, retry)
	}
}

func TestRateLimiter_BurstThenThrottle(t *testing.T) {
	// A single controllable clock makes the behaviour deterministic without
	// sleeping.
	fake := newFakeClock()
	limiter := newRateLimiter(3)
	limiter.now = fake.now

	// The bucket starts full (burst == limit), so the first 3 are admitted.
	for i := 0; i < 3; i++ {
		if allowed, _ := limiter.allow(); !allowed {
			t.Fatalf("expected admission %d within the burst", i)
		}
	}
	// The 4th within the same instant is rejected.
	allowed, retry := limiter.allow()
	if allowed {
		t.Fatal("expected rejection after burst exhausted")
	}
	if retry < time.Second {
		t.Fatalf("expected at least one second Retry-After, got %v", retry)
	}

	// After one second the bucket has refilled ~3 tokens.
	fake.advance(time.Second)
	allowed, _ = limiter.allow()
	if !allowed {
		t.Fatal("expected admission after one second of refill")
	}
	allowed, _ = limiter.allow()
	if !allowed {
		t.Fatal("expected second admission after refill")
	}
	allowed, _ = limiter.allow()
	if !allowed {
		t.Fatal("expected third admission after refill")
	}
	// Burst is capped at the limit: it cannot accumulate beyond 3.
	if allowed, _ := limiter.allow(); allowed {
		t.Fatal("burst must be capped at the limit")
	}
}

func TestRateLimiter_RateFasterThanBurst(t *testing.T) {
	// With a small rate, refill between one second steps is partial.
	fake := newFakeClock()
	limiter := newRateLimiter(1) // 1 token/second, burst 1
	limiter.now = fake.now

	if allowed, _ := limiter.allow(); !allowed {
		t.Fatal("expected the initial burst token")
	}
	if allowed, _ := limiter.allow(); allowed {
		t.Fatal("expected rejection immediately after the burst")
	}
	fake.advance(500 * time.Millisecond)
	if allowed, _ := limiter.allow(); allowed {
		t.Fatal("expected rejection after a sub-second advance at 1 tok/s")
	}
	fake.advance(500 * time.Millisecond)
	if allowed, _ := limiter.allow(); !allowed {
		t.Fatal("expected admission after a full second")
	}
}

// TestRateLimiter_Concurrent proves the bucket is race-safe and, under a fully
// serialized admission gate, admits exactly the burst count.
func TestRateLimiter_Concurrent(t *testing.T) {
	limiter := newRateLimiter(5)
	const n = 50
	// Serialize the admission decision across goroutines so the count is exact
	// and independent of scheduling, while still exercising the limiter's own
	// mutex under the -race detector.
	var mu sync.Mutex
	allowed := int32(0)
	for i := 0; i < n; i++ {
		mu.Lock()
		if ok, _ := limiter.allow(); ok {
			atomic.AddInt32(&allowed, 1)
		}
		mu.Unlock()
	}
	if got := atomic.LoadInt32(&allowed); got != 5 {
		t.Fatalf("expected exactly 5 admissions from a burst of 5, got %d", got)
	}
}

func TestRateLimitMiddleware_NoLimitPassesThrough(t *testing.T) {
	// A non-positive limit returns the next handler unchanged.
	inner := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	if h := NewRateLimitMiddleware(0, inner); !passesThrough(h, inner) {
		t.Fatal("zero limit must return the wrapped handler unchanged")
	}
	if h := NewRateLimitMiddleware(-7, inner); !passesThrough(h, inner) {
		t.Fatal("negative limit must return the wrapped handler unchanged")
	}
}

func passesThrough(h http.Handler, inner http.Handler) bool {
	// The returned handler must be identical to the inner handler for a
	// disabled limit, so it forwards every request without limiting.
	_, ok := h.(*rateLimitMiddleware)
	return !ok
}

func TestRateLimitMiddleware_Returns429WithRetryAfter(t *testing.T) {
	inner := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	fake := newFakeClock()
	limiter := newRateLimiter(2)
	limiter.now = fake.now
	mw := rateLimitMiddleware{limiter: limiter, next: inner}

	// Admit the two-token burst, then the next request must be shed with 429.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected non-200 for burst admission %d, got %d", i, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after the burst, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "rate_limited") {
		t.Fatalf("expected rate_limited error body, got %q", body)
	}
	if retry := rec.Header().Get("Retry-After"); retry == "" {
		t.Fatal("expected a Retry-After header on the 429")
	}
	if ctype := rec.Header().Get("Content-Type"); ctype != "application/json" {
		t.Fatalf("expected application/json content type, got %q", ctype)
	}

	// After one second the bucket refills and requests are admitted again.
	fake.advance(time.Second)
	rec = httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 after refill, got %d", rec.Code)
	}
}

func TestRateLimitMiddleware_ForwardsWhenUnderLimit(t *testing.T) {
	fake := newFakeClock()
	limiter := newRateLimiter(10)
	limiter.now = fake.now
	var forwarded atomic.Int32
	inner := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		forwarded.Add(1)
		rw.WriteHeader(http.StatusOK)
	})
	mw := rateLimitMiddleware{limiter: limiter, next: inner}
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 under the limit, got %d", rec.Code)
	}
	if got := forwarded.Load(); got != 1 {
		t.Fatalf("expected exactly one forwarded request, got %d", got)
	}
}

type fakeClock struct{ t time.Time }

func newFakeClock() *fakeClock      { return &fakeClock{t: time.Unix(0, 0)} }
func (f *fakeClock) now() time.Time { return f.t }
func (f *fakeClock) advance(d time.Duration) {
	f.t = f.t.Add(d)
}

// TestPerConnGate_DisabledAlwaysAllows confirms that a non-positive limit makes
// the gate a permissive no-op, matching the "0/omitted disables limiting"
// contract for non-HTTP (e.g. SOCKS5) listeners.
func TestPerConnGate_DisabledAlwaysAllows(t *testing.T) {
	for _, limit := range []int{0, -1} {
		gate := NewPerConnGate(limit)
		for i := 0; i < 50; i++ {
			if !gate.Allow() {
				t.Fatalf("disabled gate (limit %d) must always allow (iteration %d)", limit, i)
			}
		}
	}
}

// TestPerConnGate_ShedsAfterBurstWithRefill proves the per-listener accept gate
// admits up to the burst, sheds the next accepts, and refills over time — the
// behaviour the SOCKS5 server relies on to close over-limit connections instead
// of exhausting itself.
func TestPerConnGate_ShedsAfterBurstWithRefill(t *testing.T) {
	fake := newFakeClock()
	gate := NewPerConnGate(2) // 2 accepts/second, burst 2
	gate.limiter.now = fake.now

	for i := 0; i < 2; i++ {
		if !gate.Allow() {
			t.Fatalf("expected burst admission %d", i)
		}
	}
	if gate.Allow() {
		t.Fatal("expected the third accept to be shed within the burst window")
	}
	// One second of elapsed time refills ~2 tokens; accepts resume.
	fake.advance(time.Second)
	if !gate.Allow() {
		t.Fatal("expected admission after one second of refill")
	}
}

// TestPerConnGate_Concurrent proves the gate is race-safe and admits exactly the
// burst under a serialized decision, exercising its mutex under -race.
func TestPerConnGate_Concurrent(t *testing.T) {
	gate := NewPerConnGate(3)
	const n = 50
	var mu sync.Mutex
	allowed := int32(0)
	for i := 0; i < n; i++ {
		mu.Lock()
		if gate.Allow() {
			atomic.AddInt32(&allowed, 1)
		}
		mu.Unlock()
	}
	if got := atomic.LoadInt32(&allowed); got != 3 {
		t.Fatalf("expected exactly 3 admissions from a burst of 3, got %d", got)
	}
}
