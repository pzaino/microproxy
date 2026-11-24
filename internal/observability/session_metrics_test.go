package observability

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsStore_SessionAndEndpointOutcomes(t *testing.T) {
	t.Parallel()
	store := newMetricsStore()
	store.recordSessionOutcome("sticky", SessionOutcomeRotated)
	store.recordSessionOutcome("sticky", SessionOutcomeRotated)
	store.recordSessionOutcome("sticky", SessionOutcomeReplayed)
	store.recordSessionOutcome("sticky", SessionOutcomeStale)
	store.recordSessionOutcome("sticky", "not-a-real-outcome")
	store.recordEndpointOutcome("sticky", "upstream.example", nil)
	store.recordEndpointOutcome("sticky", "upstream.example", errors.New("boom"))

	rr := httptest.NewRecorder()
	store.handlePrometheus(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()

	expected := []string{
		`microproxy_session_rotations_total{provider="sticky",outcome="rotated"} 2`,
		`microproxy_session_rotations_total{provider="sticky",outcome="replayed"} 1`,
		`microproxy_session_rotations_total{provider="sticky",outcome="stale"} 1`,
		`microproxy_session_rotations_total{provider="sticky",outcome="failed"} 1`,
		`microproxy_upstream_endpoint_attempts_total{provider="sticky",endpoint="upstream.example",outcome="success"} 1`,
		`microproxy_upstream_endpoint_attempts_total{provider="sticky",endpoint="upstream.example",outcome="failure"} 1`,
	}
	for _, line := range expected {
		if !strings.Contains(body, line) {
			t.Errorf("expected metrics line %q in:\n%s", line, body)
		}
	}
}

func TestMetricsStore_OutcomeLabelsAreBounded(t *testing.T) {
	t.Parallel()
	store := newMetricsStore()
	// An unexpected outcome must not become an unbounded label value.
	store.recordSessionOutcome("provider|with|pipes", "caller-supplied-value")
	store.recordEndpointOutcome("", "", errors.New("boom"))

	rr := httptest.NewRecorder()
	store.handlePrometheus(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()

	if strings.Contains(body, "caller-supplied-value") {
		t.Fatalf("unknown outcome leaked into metric labels:\n%s", body)
	}
	if !strings.Contains(body, `microproxy_session_rotations_total{provider="provider|with|pipes",outcome="failed"} 1`) {
		t.Fatalf("expected failed outcome for provider label, got:\n%s", body)
	}
	if !strings.Contains(body, `microproxy_upstream_endpoint_attempts_total{provider="unknown",endpoint="direct",outcome="failure"} 1`) {
		t.Fatalf("expected unknown/direct endpoint labels, got:\n%s", body)
	}
}

func TestMetricsStore_DoesNotLeakCredentialShapedLabels(t *testing.T) {
	t.Parallel()
	store := newMetricsStore()
	// The session API and registry only pass provider/outcome/endpoint-host
	// labels. This test freezes the emitted label set so a future caller cannot
	// accidentally add a session identity or credential without a visible test
	// change.
	store.recordSessionOutcome("sticky", SessionOutcomeRotated)
	store.recordEndpointOutcome("sticky", "upstream.example", nil)

	rr := httptest.NewRecorder()
	store.handlePrometheus(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	for _, secret := range []string{"session_id", "username", "password", "authorization", "idempotency"} {
		if strings.Contains(strings.ToLower(body), secret) {
			t.Fatalf("metrics output unexpectedly contains %q:\n%s", secret, body)
		}
	}
}
