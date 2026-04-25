package listeners

import (
	"net/http"
	"testing"
)

func TestRemoveHopHeadersRequestHeaderConnectionTokens(t *testing.T) {
	headers := http.Header{}
	headers.Set("Connection", "keep-alive, x-foo")
	headers.Set("Keep-Alive", "timeout=5")
	headers.Set("X-Foo", "remove-me")
	headers.Set("X-Bar", "keep-me")

	removeHopHeaders(headers)

	if got := headers.Get("X-Foo"); got != "" {
		t.Fatalf("expected X-Foo to be removed, got %q", got)
	}
	if got := headers.Get("Keep-Alive"); got != "" {
		t.Fatalf("expected Keep-Alive to be removed, got %q", got)
	}
	if got := headers.Get("Connection"); got != "" {
		t.Fatalf("expected Connection to be removed, got %q", got)
	}
	if got := headers.Get("X-Bar"); got != "keep-me" {
		t.Fatalf("expected X-Bar to be kept, got %q", got)
	}
}

func TestRemoveHopHeadersResponseHeaderConnectionTokens(t *testing.T) {
	headers := http.Header{}
	headers.Add("Connection", "keep-alive")
	headers.Add("Connection", "x-foo")
	headers.Set("Keep-Alive", "timeout=5")
	headers.Set("X-Foo", "remove-me")
	headers.Set("X-Bar", "keep-me")

	removeHopHeaders(headers)

	if got := headers.Get("X-Foo"); got != "" {
		t.Fatalf("expected X-Foo to be removed, got %q", got)
	}
	if got := headers.Get("Keep-Alive"); got != "" {
		t.Fatalf("expected Keep-Alive to be removed, got %q", got)
	}
	if got := headers.Get("Connection"); got != "" {
		t.Fatalf("expected Connection to be removed, got %q", got)
	}
	if got := headers.Get("X-Bar"); got != "keep-me" {
		t.Fatalf("expected X-Bar to be kept, got %q", got)
	}
}
