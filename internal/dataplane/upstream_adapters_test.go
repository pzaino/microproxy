package dataplane

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/pzaino/microproxy/pkg/config"
)

func TestApplyProxyAuth_BasicFromEndpointUserInfoWhenAuthUnset(t *testing.T) {
	t.Parallel()

	headers := http.Header{}
	endpoint, err := url.Parse("http://brd-customer-zone-country-us:secret@brd.superproxy.io:33335")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	applyProxyAuth(headers, config.ProviderAuthConfig{}, endpoint)

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("brd-customer-zone-country-us:secret"))
	if got := headers.Get("Proxy-Authorization"); got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestApplyProxyAuth_ExplicitAuthOverridesEndpointUserInfo(t *testing.T) {
	t.Parallel()

	headers := http.Header{}
	endpoint, err := url.Parse("http://ignored-user:ignored-pass@brd.superproxy.io:33335")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	applyProxyAuth(headers, config.ProviderAuthConfig{Type: "basic", Username: "cfg-user", Password: "cfg-pass"}, endpoint)

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("cfg-user:cfg-pass"))
	if got := headers.Get("Proxy-Authorization"); got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
