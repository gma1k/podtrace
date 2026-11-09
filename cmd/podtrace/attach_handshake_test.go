package main

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/kubernetes/nodespawn"
)

func TestAwaitSpawnAttach(t *testing.T) {
	orig := nodespawn.AttachHandshakeTimeout
	t.Cleanup(func() { nodespawn.AttachHandshakeTimeout = orig })
	nodespawn.AttachHandshakeTimeout = 20 * time.Millisecond

	t.Setenv(nodespawn.EnvNodeLocalSentinel, "")
	t.Setenv(nodespawn.EnvAttachHandshake, "1")
	r, w := io.Pipe()
	defer func() { _ = w.Close() }()
	start := time.Now()
	awaitSpawnAttach(r)
	if time.Since(start) > 10*time.Millisecond {
		t.Error("a workstation run must not wait for a handshake")
	}

	t.Setenv(nodespawn.EnvNodeLocalSentinel, "1")
	t.Setenv(nodespawn.EnvAttachHandshake, "")
	start = time.Now()
	awaitSpawnAttach(r)
	if time.Since(start) > 10*time.Millisecond {
		t.Error("a spawn pod built without the handshake must not wait")
	}

	t.Setenv(nodespawn.EnvAttachHandshake, "1")
	awaitSpawnAttach(strings.NewReader("\n"))

	start = time.Now()
	awaitSpawnAttach(r)
	if waited := time.Since(start); waited < 20*time.Millisecond || waited > time.Second {
		t.Errorf("waited %s, want the bounded handshake timeout", waited)
	}
}
