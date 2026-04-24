package dataplane

import (
	"context"
)

// ListenerManager controls lifecycle of data-plane listeners.
type ListenerManager interface {
	Start(context.Context) error
	Shutdown(context.Context) error
}

// NoopListenerManager is a bootstrap-safe placeholder manager.
type NoopListenerManager struct{}

func (NoopListenerManager) Start(context.Context) error {
	return nil
}

func (NoopListenerManager) Shutdown(context.Context) error {
	return nil
}
