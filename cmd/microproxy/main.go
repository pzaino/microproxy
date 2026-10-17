package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
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
	flag.StringVar(&healthAddr, "health-addr", "", "optional liveness listen address; overrides observability.health_endpoints.liveness_address")
	flag.Parse()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := applyHealthAddressOverride(cfg, healthAddr); err != nil {
		return err
	}

	observabilityManager := observability.NewListenerManager(cfg)
	// One live SessionManager is shared by the data-plane listeners and the
	// local session management API so rotation affects new operations
	// immediately without a restart.
	sessionManager, err := dataplane.NewSessionManager(cfg)
	if err != nil {
		return fmt.Errorf("init session manager: %w", err)
	}
	dataPlaneManager := dataplane.NewListenerManagerWithSessionManager(cfg, sessionManager)
	sessionAPI := dataplane.NewSessionAPIServer(cfg, sessionManager, func() {
		if closer, ok := dataPlaneManager.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	})

	svcCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	if err := dataPlaneManager.Start(svcCtx); err != nil {
		return fmt.Errorf("start data-plane manager: %w", err)
	}
	if sessionAPI != nil {
		if err := sessionAPI.Start(svcCtx); err != nil {
			_ = dataPlaneManager.Shutdown(context.Background())
			return fmt.Errorf("start session api: %w", err)
		}
	}
	if err := observabilityManager.Start(svcCtx); err != nil {
		if sessionAPI != nil {
			_ = sessionAPI.Shutdown(context.Background())
		}
		_ = dataPlaneManager.Shutdown(context.Background())
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
	if sessionAPI != nil {
		if err := sessionAPI.Shutdown(shutdownCtx); err != nil {
			shutdownErr = errors.Join(shutdownErr, fmt.Errorf("shutdown session api: %w", err))
		}
	}
	if err := dataPlaneManager.Shutdown(shutdownCtx); err != nil {
		shutdownErr = errors.Join(shutdownErr, fmt.Errorf("shutdown data-plane manager: %w", err))
	}

	return shutdownErr
}

// applyHealthAddressOverride applies the optional CLI liveness override. An
// empty flag leaves the YAML value untouched. When overridden, the effective
// configuration is revalidated before any listener starts, so port conflicts
// with enabled listeners, session control, metrics, or other health endpoints
// fail startup with a clear error.
func applyHealthAddressOverride(cfg *config.Config, healthAddr string) error {
	override := strings.TrimSpace(healthAddr)
	if override == "" {
		return nil
	}
	if cfg == nil {
		return errors.New("-health-addr override requires a configuration")
	}
	cfg.Observability.HealthEndpoints.LivenessAddress = override
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid -health-addr override %q: %w", override, err)
	}
	return nil
}
