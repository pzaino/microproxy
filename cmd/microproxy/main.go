package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane"
	"github.com/pzaino/microproxy/internal/observability"
	"github.com/pzaino/microproxy/pkg/config"
)

func main() {
	if err := run(); err != nil {
		log.Printf("microproxy exited with error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "path to configuration file (.yaml, .yml, .json)")
	healthAddr := flag.String("health-addr", ":9090", "control-plane health server listen address")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dataplaneManager := dataplane.NoopListenerManager{}
	observabilityManager := observability.NoopListenerManager{}

	if err := dataplaneManager.Start(ctx); err != nil {
		return fmt.Errorf("start dataplane manager: %w", err)
	}
	if err := observabilityManager.Start(ctx); err != nil {
		return fmt.Errorf("start observability manager: %w", err)
	}

	healthServer := newHealthServer(*healthAddr)
	healthErrCh := make(chan error, 1)
	go func() {
		if err := healthServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			healthErrCh <- err
			return
		}
		healthErrCh <- nil
	}()

	log.Printf("microproxy bootstrap complete (http=%q https=%q socks5=%q health=%q)", cfg.MicroProxy.HTTPProto, cfg.MicroProxy.HTTPSProto, cfg.MicroProxy.SOCKS5Proto, *healthAddr)

	select {
	case err := <-healthErrCh:
		if err != nil {
			return fmt.Errorf("health server failed: %w", err)
		}
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown health server: %w", err)
	}
	if err := observabilityManager.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown observability manager: %w", err)
	}
	if err := dataplaneManager.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown dataplane manager: %w", err)
	}

	return nil
}

func newHealthServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}
