package main

import (
	"testing"
	"time"
)

func TestShutdownTimeout(t *testing.T) {
	if shutdownTimeout != 10*time.Second {
		t.Fatalf("expected shutdownTimeout to be 10s, got %v", shutdownTimeout)
	}
}
