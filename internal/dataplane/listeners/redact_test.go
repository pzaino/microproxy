package listeners

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestWrapEndpointError_RedactsUserinfo(t *testing.T) {
	// A dial/TLS error that embeds the upstream endpoint's URL (which carries
	// basic-auth userinfo) must be redacted when wrapped so the password never
	// reaches logs, the 502/503 body, or any caller.
	u, err := url.Parse("http://top-secret-user:s3cret-pass@upstream.example:3128")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	inner := fmt.Errorf("dial http://top-secret-user:s3cret-pass@upstream.example:3128: connection refused")

	wrapped := wrapEndpointError(u, inner, TimeoutClassification("connect_timeout"))
	msg := wrapped.Error()

	if strings.Contains(msg, "s3cret-pass") {
		t.Fatalf("wrapped error leaked the upstream password: %q", msg)
	}
	// The username and host are preserved so the log line stays useful.
	if !strings.Contains(msg, "top-secret-user") {
		t.Fatalf("wrapped error dropped the username: %q", msg)
	}
	if !strings.Contains(msg, "upstream.example") {
		t.Fatalf("wrapped error dropped the host: %q", msg)
	}
	if !strings.Contains(msg, "****") {
		t.Fatalf("wrapped error did not mask the password: %q", msg)
	}
	// The original error must remain available for errors.Is/errors.As.
	if !errors.Is(wrapped, inner) {
		t.Fatal("wrapped error must preserve the original error via errors.Is")
	}
}

func TestWrapEndpointError_RedactsOnReformat(t *testing.T) {
	// Redaction must survive a later reformat of the error (e.g. wrapping it
	// again in slog), otherwise an operator re-log could re-leak the secret.
	u, _ := url.Parse("http://user:pass@upstream.example:3128")
	wrapped := wrapEndpointError(u, fmt.Errorf("connect: %s", "http://user:pass@upstream.example:3128 refused"), TimeoutClassification("connect_timeout"))
	// Re-wrapping with %w and then formatting again must still redact.
	rewrapped := fmt.Errorf("outer: %w", wrapped)
	if strings.Contains(rewrapped.Error(), "pass") {
		t.Fatalf("reformatted wrapped error leaked the password: %q", rewrapped.Error())
	}
}

func TestWrapEndpointError_NilEndpointNoLeak(t *testing.T) {
	// The legacy direct path (nil endpoint) must not panic and must surface the
	// cause through errors.Is.
	cause := errors.New("direct dial failed")
	wrapped := wrapEndpointError(nil, cause, TimeoutClassification("connect_timeout"))
	if !strings.Contains(wrapped.Error(), "direct dial failed") {
		t.Fatalf("expected the direct error to surface, got %q", wrapped.Error())
	}
	if !errors.Is(wrapped, cause) {
		t.Fatal("wrapped direct error must preserve the cause via errors.Is")
	}
}
