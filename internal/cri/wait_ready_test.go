package cri

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/connectivity"
)

func TestWaitForReady_BecomesReady(t *testing.T) {
	conn := startFakeCRIServer(t, nil)

	conn.Connect()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := waitForReady(ctx, conn); err != nil {
		t.Fatalf("waitForReady on a live bufconn server should succeed, got %v", err)
	}
	if got := conn.GetState(); got != connectivity.Ready {
		t.Errorf("connection state = %v, want Ready", got)
	}
}
