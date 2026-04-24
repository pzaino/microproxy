package dataplane

import (
	"context"
	"testing"
	"time"

	"github.com/pzaino/microproxy/pkg/config"
)

func TestNewListenerManager_FallbackToNoop(t *testing.T) {
	t.Parallel()

	mgr := NewListenerManager(nil)
	if _, ok := mgr.(NoopListenerManager); !ok {
		t.Fatalf("expected NoopListenerManager, got %T", mgr)
	}

	cfg := &config.Config{
		Listeners: []config.ListenerConfig{{Name: "socks", Type: "socks5", Address: ":1080", Enabled: true}},
	}
	mgr = NewListenerManager(cfg)
	if _, ok := mgr.(NoopListenerManager); !ok {
		t.Fatalf("expected NoopListenerManager for non-http listeners, got %T", mgr)
	}
}

func TestNewListenerManager_ConcreteForHTTP(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Listeners: []config.ListenerConfig{{Name: "http", Type: "http", Address: "127.0.0.1:0", Enabled: true}},
	}

	mgr := NewListenerManager(cfg)
	httpMgr, ok := mgr.(*HTTPListenerManager)
	if !ok {
		t.Fatalf("expected *HTTPListenerManager, got %T", mgr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := httpMgr.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if err := httpMgr.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}
