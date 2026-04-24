package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pzaino/microproxy/internal/controlplane/api"
	"github.com/pzaino/microproxy/pkg/config"
)

func main() {
	var (
		configPath = flag.String("config", "", "path to config file (.yaml/.yml/.json)")
		listenAddr = flag.String("listen-addr", ":8081", "control-plane listen address")
	)
	flag.Parse()

	cfg := config.NewConfig()
	if *configPath != "" {
		loadedCfg, err := config.LoadConfig(*configPath)
		if err != nil {
			slog.Error("failed to load config", "error", err)
			os.Exit(1)
		}
		cfg = loadedCfg
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("starting control-plane API", "address", *listenAddr)
	if err := api.Serve(ctx, *listenAddr, cfg); err != nil {
		slog.Error("control-plane API exited with error", "error", err)
		os.Exit(1)
	}
	slog.Info("control-plane API stopped")
}
