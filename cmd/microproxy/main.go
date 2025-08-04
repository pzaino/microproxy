package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
	config "github.com/pzaino/microproxy/pkg/config"
	"golang.org/x/net/proxy"
)

var (
	reqCount  int64
	respCount int64
	configMu  sync.RWMutex
	cfg       *config.Config
)

// ProxyManager manages a list of upstream proxies
type ProxyManager struct {
	proxies []string
	current int
	mutex   sync.Mutex
}

func NewProxyManager(proxies []string) *ProxyManager {
	return &ProxyManager{proxies: proxies}
}

func (pm *ProxyManager) GetNextProxy() string {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	if len(pm.proxies) == 0 {
		return ""
	}
	proxy := pm.proxies[pm.current]
	pm.current = (pm.current + 1) % len(pm.proxies)
	return proxy
}

func CustomRoundTripper(base *http.Transport) goproxy.RoundTripper {
	return goproxy.RoundTripperFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
		return base.RoundTrip(req)
	})
}

func handleSignals(reload func()) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	go func() {
		for range sigCh {
			log.Println("Reloading config due to SIGHUP")
			reload()
		}
	}()
}

func reloadConfig(path string, pm *ProxyManager) {
	configMu.Lock()
	defer configMu.Unlock()
	newCfg, err := config.LoadConfig(path)
	if err != nil {
		log.Printf("Failed to reload config: %v", err)
		return
	}
	cfg = newCfg
	pm.proxies = cfg.UpstreamProxy.Proxies
	log.Println("Configuration reloaded successfully")
}

func startSOCKS5Listener(addr string, pm *ProxyManager) {
	if addr == "" {
		return
	}
	go func() {
		log.Printf("SOCKS5 proxy listening on %s", addr)
		dialer := proxy.Direct
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("Failed to start SOCKS5 listener: %v", err)
		}
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("SOCKS5 accept error: %v", err)
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				upstream := pm.GetNextProxy()
				up, _ := url.Parse(upstream)
				t, err := dialer.Dial("tcp", up.Host)
				if err != nil {
					log.Printf("Failed to dial upstream: %v", err)
					return
				}
				defer t.Close()
				go func() {
					if _, err := io.Copy(t, c); err != nil {
						log.Printf("Error copying from client to upstream: %v", err)
					}
				}()
				if _, err := io.Copy(c, t); err != nil {
					log.Printf("Error copying from upstream to client: %v", err)
				}
			}(conn)
		}
	}()
}

func main() {
	rand.Seed(time.Now().UnixNano())

	configPath := "config.yaml"
	initialCfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	cfg = initialCfg

	proxyManager := NewProxyManager(cfg.UpstreamProxy.Proxies)
	handleSignals(func() { reloadConfig(configPath, proxyManager) })
	startSOCKS5Listener(cfg.MicroProxy.SOCKS5Proto, proxyManager)

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true

	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		atomic.AddInt64(&reqCount, 1)

		upstream := proxyManager.GetNextProxy()
		proxyURL, err := url.Parse(upstream)
		if err != nil {
			return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusBadGateway, "Invalid proxy")
		}
		ctx.RoundTripper = CustomRoundTripper(&http.Transport{Proxy: http.ProxyURL(proxyURL)})

		ipStr, _, _ := net.SplitHostPort(r.RemoteAddr)
		clientIP := net.ParseIP(ipStr)
		username, password := cfg.UpstreamProxy.GetCredentialsFor(clientIP)
		if username != "" && password != "" {
			auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
			r.Header.Set("Proxy-Authorization", "Basic "+auth)
		}
		return r, nil
	})

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		atomic.AddInt64(&respCount, 1)
		return resp
	})

	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile(".*"))).
		HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			return goproxy.OkConnect, host
		}))

	addr := cfg.MicroProxy.HTTPProto
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("HTTP proxy listening on %s", addr)

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "requests_total %d\nresponses_total %d\n", reqCount, respCount)
	})
	go func() {
		if err := http.ListenAndServe(":9091", nil); err != nil {
			log.Printf("Metrics server error: %v", err)
		}
	}()

	server := &http.Server{
		Addr:         addr,
		Handler:      proxy,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
