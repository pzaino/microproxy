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

}

func TestNewListenerManager_CompositeForEnabledListeners(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Listeners: []config.ListenerConfig{
			{Name: "http", Type: "http", Address: "127.0.0.1:0", Enabled: true},
			{Name: "socks", Type: "socks5", Address: "127.0.0.1:0", Enabled: true},
		},
	}

	mgr := NewListenerManager(cfg)
	composite, ok := mgr.(*CompositeListenerManager)
	if !ok {
		t.Fatalf("expected *CompositeListenerManager, got %T", mgr)
	}
	if len(composite.managers) != 2 {
		t.Fatalf("expected 2 managers, got %d", len(composite.managers))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := composite.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if err := composite.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}
