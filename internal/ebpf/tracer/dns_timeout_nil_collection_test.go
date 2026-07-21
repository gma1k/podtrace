package tracer

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestRecordDNSDrops_NilCollectionReturnsEarly(t *testing.T) {
	tr := &Tracer{}
	tr.recordDNSDrops()
	if tr.lastDNSDrops != 0 {
		t.Errorf("lastDNSDrops = %d, want 0 when collection is nil", tr.lastDNSDrops)
	}
}

func TestSweepDNSTimeouts_NilCollectionEmitsNothing(t *testing.T) {
	tr := &Tracer{}
	ch := make(chan *events.Event, 1)
	tr.sweepDNSTimeouts(context.Background(), ch)
	if len(ch) != 0 {
		t.Errorf("emitted %d events with a nil collection, want 0", len(ch))
	}
}

func TestRunDNSTimeoutSweeper_ReturnsOnCancelledContext(t *testing.T) {
	tr := &Tracer{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch := make(chan *events.Event, 1)

	done := make(chan struct{})
	go func() {
		tr.runDNSTimeoutSweeper(ctx, ch)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runDNSTimeoutSweeper did not return on a cancelled context")
	}
}
