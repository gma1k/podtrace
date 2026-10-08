package main

import (
	"context"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestTheNetFilterKeepsTLSHandshakes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan *events.Event, 2)
	out := make(chan *events.Event, 2)
	go filterEvents(ctx, in, out, "net")
	in <- &events.Event{Type: events.EventTLSHandshake, Error: -1}
	select {
	case e := <-out:
		if e.Type != events.EventTLSHandshake {
			t.Errorf("got %v", e.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a session filtered to net dropped the TLS handshake a tls.handshake_failure_rate issue started it for")
	}
}
