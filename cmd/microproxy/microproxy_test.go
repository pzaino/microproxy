package main

// File: microproxy_test.go

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyManagerRoundRobin(t *testing.T) {
	pm := NewProxyManager([]string{"http://proxy1:8080", "http://proxy2:8080"})

	seen := make(map[string]bool)
	for i := 0; i < 4; i++ {
		proxy := pm.GetNextProxy()
		seen[proxy] = true
	}

	if len(seen) != 2 {
		t.Errorf("expected round robin to cycle through 2 proxies, got %d", len(seen))
	}
}

func TestCustomRoundTripper(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	transport := &http.Transport{}
	rt := CustomRoundTripper(transport)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := rt.RoundTrip(req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %v", resp.StatusCode)
	}
}
