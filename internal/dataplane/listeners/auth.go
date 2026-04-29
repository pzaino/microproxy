package listeners

import (
	"encoding/base64"
	"net/http"
	"strings"
)

func ListenerAuthMiddleware(authType, username, password string, next http.Handler) http.Handler {
	mode := strings.ToLower(strings.TrimSpace(authType))
	if next == nil {
		next = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}
	if mode == "" || mode == "none" {
		return next
	}
	if mode != "basic" {
		return http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			http.Error(rw, "unsupported listener auth type", http.StatusInternalServerError)
		})
	}

	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if subtleEqual(req.Header.Get("Proxy-Authorization"), expected) || subtleEqual(req.Header.Get("Authorization"), expected) {
			next.ServeHTTP(rw, req)
			return
		}
		rw.Header().Set("Proxy-Authenticate", `Basic realm="microproxy"`)
		http.Error(rw, "proxy authentication required", http.StatusProxyAuthRequired)
	})
}

func subtleEqual(a, b string) bool {
	return strings.TrimSpace(a) == strings.TrimSpace(b)
}
