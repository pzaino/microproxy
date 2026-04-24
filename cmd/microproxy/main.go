package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane"
	"github.com/pzaino/microproxy/internal/observability"
	"github.com/pzaino/microproxy/pkg/config"
)

const shutdownTimeout = 10 * time.Second

func main() {
	if err := run(); err != nil {
		log.Fatalf("microproxy failed: %v", err)
	}
}

func run() error {
	var configPath string
	var healthAddr string

	flag.StringVar(&configPath, "config", "", "path to configuration file (.yaml/.yml/.json)")
	flag.StringVar(&healthAddr, "health-addr", ":9090", "health endpoint listen address")
	flag.Parse()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if healthAddr != "" {
		cfg.Observability.HealthEndpoints.LivenessAddress = healthAddr
	}

	dataPlaneManager := dataplane.NoopListenerManager{}
	observabilityManager := observability.NoopListenerManager{}

	svcCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	if err := dataPlaneManager.Start(svcCtx); err != nil {
		return fmt.Errorf("start data-plane manager: %w", err)
	}
	if err := observabilityManager.Start(svcCtx); err != nil {
		return fmt.Errorf("start observability manager: %w", err)
	}

	<-svcCtx.Done()
	log.Println("shutdown signal received; stopping managers")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var shutdownErr error
	if err := observabilityManager.Shutdown(shutdownCtx); err != nil {
		shutdownErr = errors.Join(shutdownErr, fmt.Errorf("shutdown observability manager: %w", err))
	}
	if err := dataPlaneManager.Shutdown(shutdownCtx); err != nil {
		shutdownErr = errors.Join(shutdownErr, fmt.Errorf("shutdown data-plane manager: %w", err))
	}

	return shutdownErr
}
