package kubernetes_test

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/kubernetes"
)

func TestChannelTargetSource_StartEmitsEmptyOnInitialState(t *testing.T) {
	src := kubernetes.NewChannelTargetSource()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := src.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	select {
	case snap := <-src.Updates():
		if len(snap) != 0 {
			t.Fatalf("expected empty snapshot, got %d items", len(snap))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Start did not emit an initial snapshot within 1s")
	}
}

func TestChannelTargetSource_PublishPropagates(t *testing.T) {
	src := kubernetes.NewChannelTargetSource()
	if err := src.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Drain the initial snapshot.
	<-src.Updates()

	src.Publish([]*kubernetes.PodInfo{{PodName: "a", CgroupPath: "/c/a"}})
	select {
	case snap := <-src.Updates():
		if len(snap) != 1 || snap[0].PodName != "a" {
			t.Fatalf("unexpected snapshot: %+v", snap)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("publish did not propagate within 1s")
	}
}

func TestChannelTargetSource_LatestWinsOnSlowConsumer(t *testing.T) {
	src := kubernetes.NewChannelTargetSource()
	if err := src.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Do NOT drain the initial snapshot; the internal buffer is 8 and we
	// want to exercise the "drop oldest, keep newest" fallback. Publish
	// enough times that the buffer saturates.
	for i := 0; i < 20; i++ {
		src.Publish([]*kubernetes.PodInfo{{PodName: stringN(i), CgroupPath: "/c"}})
	}

	// Drain the channel. The final element must be the newest publish
	// (i=19), regardless of how many earlier snapshots were dropped.
	var last []*kubernetes.PodInfo
	for {
		select {
		case snap := <-src.Updates():
			last = snap
		case <-time.After(100 * time.Millisecond):
			goto done
		}
	}
done:
	if len(last) != 1 || last[0].PodName != stringN(19) {
		t.Fatalf("latest-wins violated: got %+v", last)
	}
}

func TestChannelTargetSource_PublishBeforeStartIsQueuedAsLatest(t *testing.T) {
	src := kubernetes.NewChannelTargetSource()

	// Publish before Start: should be stored as the latest snapshot but
	// NOT delivered (started=false). Start then emits it.
	src.Publish([]*kubernetes.PodInfo{{PodName: "pre", CgroupPath: "/c"}})
	if err := src.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case snap := <-src.Updates():
		if len(snap) != 1 || snap[0].PodName != "pre" {
			t.Fatalf("Start did not emit the pre-start snapshot: %+v", snap)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Start did not emit the pre-start snapshot within 1s")
	}
}

func TestChannelTargetSource_Snapshot(t *testing.T) {
	src := kubernetes.NewChannelTargetSource()
	if err := src.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-src.Updates()

	src.Publish([]*kubernetes.PodInfo{{PodName: "a"}, {PodName: "b"}})
	// Allow the emit to complete.
	<-src.Updates()

	snap := src.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot length: got %d want 2", len(snap))
	}

	// Snapshot must return a defensive copy: mutating it must not affect
	// subsequent Snapshot calls.
	snap[0] = nil
	again := src.Snapshot()
	if again[0] == nil {
		t.Fatal("Snapshot returned a shared slice")
	}
}

func TestToTracerTargets_SkipsNilAndEmpty(t *testing.T) {
	in := []*kubernetes.PodInfo{
		nil,
		{PodName: "has-cgroup", CgroupPath: "/c/1", Labels: map[string]string{"app": "api"}},
		{PodName: "no-cgroup", CgroupPath: ""}, // ToTracerTargets keeps empty-cgroup rows; engine filters them.
	}
	out := kubernetes.ToTracerTargets(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(out))
	}
	if out[0].PodName != "has-cgroup" || out[0].Labels["app"] != "api" {
		t.Errorf("first target lost data: %+v", out[0])
	}
	// Labels must be a copy, not aliased.
	out[0].Labels["app"] = "mutated"
	if in[1].Labels["app"] == "mutated" {
		t.Error("ToTracerTargets aliased labels map")
	}
}

// TestChannelTargetSource_CloseClosesUpdatesChannel asserts that Close
// terminates consumers observing Updates(): receives on a closed channel
// return immediately with the zero value and ok=false.
func TestChannelTargetSource_CloseClosesUpdatesChannel(t *testing.T) {
	src := kubernetes.NewChannelTargetSource()
	if err := src.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Drain initial snapshot so Close is the next thing on the channel.
	<-src.Updates()

	src.Close()

	select {
	case _, ok := <-src.Updates():
		if ok {
			t.Fatal("Updates() returned ok=true after Close; channel not closed")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Updates() did not unblock within 1s after Close")
	}
}

// TestChannelTargetSource_PublishAfterCloseDoesNotDeliver verifies that
// a Publish after Close neither panics (because we gate emit on started)
// nor delivers to the closed channel.
func TestChannelTargetSource_PublishAfterCloseDoesNotDeliver(t *testing.T) {
	src := kubernetes.NewChannelTargetSource()
	if err := src.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-src.Updates()
	src.Close()

	// Publish after Close: implementation must not try to send on a
	// closed channel. Recovery via defer/recover would indicate a bug.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Publish after Close panicked: %v", r)
		}
	}()
	src.Publish([]*kubernetes.PodInfo{{PodName: "late"}})
}

func stringN(i int) string {
	// small helper so names are stable and comparable without fmt import in hot path.
	switch i {
	case 0:
		return "p0"
	case 19:
		return "p19"
	default:
		return []string{"p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10", "p11", "p12", "p13", "p14", "p15", "p16", "p17", "p18"}[i-1]
	}
}

// TestChannelTargetSource_StartEmitsLatestAfterPublish guards the Start/Publish
// ordering: a snapshot published before Start (while started=false, so it is
// only stored, not emitted) must be the one Start emits — not a stale/empty
// snapshot. Draining Updates must leave the consumer on the published set.
func TestChannelTargetSource_StartEmitsLatestAfterPublish(t *testing.T) {
	src := kubernetes.NewChannelTargetSource()
	want := []*kubernetes.PodInfo{{PodName: "p1", Namespace: "ns"}}
	src.Publish(want) // stored only; not started yet

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := src.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Drain to the final delivered snapshot.
	var last []*kubernetes.PodInfo
	deadline := time.After(1 * time.Second)
	for {
		select {
		case snap := <-src.Updates():
			last = snap
		case <-time.After(50 * time.Millisecond):
			if len(last) != 1 || last[0].PodName != "p1" {
				t.Fatalf("consumer left on stale snapshot %v, want [p1]", last)
			}
			return
		case <-deadline:
			t.Fatal("timed out draining Updates")
		}
	}
}

// TestChannelTargetSource_StartIsIdempotent ensures a second Start does not
// re-emit and does not panic.
func TestChannelTargetSource_StartIsIdempotent(t *testing.T) {
	src := kubernetes.NewChannelTargetSource()
	ctx := context.Background()
	if err := src.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-src.Updates() // consume the initial empty emit
	if err := src.Start(ctx); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	select {
	case <-src.Updates():
		t.Fatal("second Start must not re-emit")
	case <-time.After(100 * time.Millisecond):
	}
}
