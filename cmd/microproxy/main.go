package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	cfg "github.com/pzaino/microproxy/pkg/config"
)

// ProxyManager manages a list of upstream proxies
type ProxyManager struct {
	proxies []string
	current int
	mutex   sync.Mutex
}

// NewProxyManager creates a new ProxyManager with a list of upstream proxies
func NewProxyManager(proxies []string) *ProxyManager {
	return &ProxyManager{
		proxies: proxies,
		current: 0,
	}
}

// GetNextProxy returns the next proxy in the list (round-robin)
func (pm *ProxyManager) GetNextProxy() string {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	proxy := pm.proxies[pm.current]
	pm.current = (pm.current + 1) % len(pm.proxies)
	return proxy
}

// CustomRoundTripper satisfies goproxy.RoundTripper
func CustomRoundTripper(base *http.Transport) goproxy.RoundTripper {
	return goproxy.RoundTripperFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
		return base.RoundTrip(req)
	})
}

func main() {
	conf, err := cfg.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	proxyList := regexp.MustCompile(",").Split(conf.UpstreamProxy.UpstreamProxy, -1)
	if len(proxyList) == 0 {
		log.Fatalf("No upstream proxies configured")
	}

	proxyManager := NewProxyManager(proxyList)
	credentials := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", conf.UpstreamProxy.Username, conf.UpstreamProxy.Password)))

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true

	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		log.Printf("Request: %s %s", r.Method, r.URL.String())
		upstream := proxyManager.GetNextProxy()
		proxyURL, err := url.Parse(upstream)
		if err != nil {
			log.Printf("Invalid proxy URL: %s", upstream)
			return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusBadGateway, "Invalid upstream proxy")
		}

		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
		ctx.RoundTripper = CustomRoundTripper(transport)

		if conf.UpstreamProxy.Username != "" && conf.UpstreamProxy.Password != "" {
			r.Header.Set("Proxy-Authorization", "Basic "+credentials)
		}

		return r, nil
	})

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		log.Printf("Response: %s", resp.Status)
		return resp
	})

	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile(".*"))).HandleConnect(goproxy.AlwaysMitm)

	address := conf.MicroProxy.HTTPProto
	if address == "" {
		address = ":8080"
	}

	httpServer := &http.Server{
		Addr:         address,
		Handler:      proxy,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("Proxy server listening on %s", address)
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("Proxy server failed: %v", err)
	}
}
