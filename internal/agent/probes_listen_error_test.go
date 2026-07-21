package agent

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestProbes_RunReturnsListenError(t *testing.T) {

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	addr := ln.Addr().String()

	s := NewProbeServer(addr, 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := s.Run(ctx)
	if runErr == nil {
		t.Fatal("Run should return the bind error when the address is already in use")
	}
}
