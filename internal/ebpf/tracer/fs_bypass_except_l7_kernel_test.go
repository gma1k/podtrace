//go:build bpf_loadtest && linux

package tracer

import (
	"context"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func fsEventType(e events.EventType) bool {
	switch e {
	case events.EventRead, events.EventWrite, events.EventFsync, events.EventOpen,
		events.EventClose, events.EventUnlink, events.EventRename:
		return true
	}
	return false
}

func TestKernelBypassExceptL7KeepsFilesystemEventsInTheKernel(t *testing.T) {
	for _, tc := range []struct {
		mode       kernelagg.Mode
		wantEvents bool
	}{
		{kernelagg.ModeOn, true},
		{kernelagg.ModeBypassExceptL7, false},
		{kernelagg.ModeBypass, false},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			w := newFSWorker(t, "bypass-"+tc.mode.String())
			tr := fsTracer(t, "fentry", w)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ch := make(chan *events.Event, 1<<14)
			if err := tr.Start(ctx, ch); err != nil {
				t.Fatal(err)
			}
			if err := tr.SetCgroups([]string{w.cgroup}); err != nil {
				t.Fatal(err)
			}
			if err := tr.SetKernelAggregationMode(tc.mode); err != nil {
				t.Fatal(err)
			}
			w.run(t, "mixed")
			time.Sleep(300 * time.Millisecond)
			shipped := 0
			for done := false; !done; {
				select {
				case ev := <-ch:
					if ev.CgroupID == w.id && fsEventType(ev.Type) {
						shipped++
					}
				default:
					done = true
				}
			}
			rows, err := tr.DrainKernelMetrics()
			if err != nil {
				t.Fatal(err)
			}
			counted := fsRows(rows, w.id)
			if counted[events.EventOpen].Count == 0 || counted[events.EventClose].Count == 0 {
				t.Fatalf("opens and closes not counted in the kernel: %v", counted)
			}
			if tc.wantEvents && shipped == 0 {
				t.Fatal("no filesystem event reached userspace with aggregation on, so this test proves nothing")
			}
			if !tc.wantEvents && shipped != 0 {
				t.Errorf("%d filesystem events reached userspace in %s; the kernel already counted them", shipped, tc.mode)
			}
		})
	}
}
