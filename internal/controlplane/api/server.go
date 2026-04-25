package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/pzaino/microproxy/pkg/config"
)

const defaultShutdownTimeout = 10 * time.Second

func Serve(ctx context.Context, addr string, cfg *config.Config) error {
	router, err := NewRouterWithError(cfg)
	if err != nil {
		return fmt.Errorf("configure control-plane server: %w", err)
	}

	server := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	errCh := make(chan error, 1)
	go func() {
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("control-plane server failed: %w", err)
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("control-plane shutdown failed: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}
