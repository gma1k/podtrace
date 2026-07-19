package agent

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

type blockingExporter struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingExporter) Name() string { return "blocking" }
func (b *blockingExporter) Export(_ context.Context, _ []*events.Event) error {
	b.entered <- struct{}{}
	<-b.release
	return nil
}
func (b *blockingExporter) Close(context.Context) error { return nil }

func TestRouter_PublishBarrierWaitsForInflight(t *testing.T) {
	exp := &blockingExporter{entered: make(chan struct{}), release: make(chan struct{})}
	r := NewRouter(nil)
	r.Publish([]CRRule{mkRule("ns", "n", []uint64{1}, []events.EventType{events.EventDNS}, exp)})

	go func() {
		_ = r.Export(context.Background(), []*events.Event{{CgroupID: 1, Type: events.EventDNS}})
	}()
	<-exp.entered

	drain := r.Publish(nil)
	done := make(chan struct{})
	go func() { drain.Wait(); close(done) }()

	select {
	case <-done:
		t.Fatal("drain returned before the in-flight export finished")
	case <-time.After(50 * time.Millisecond):
	}

	close(exp.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not return after the export finished")
	}
}
