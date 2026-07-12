package tracer_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/podtrace/podtrace/pkg/tracer"
)

// targetErrObserver records OnTargetError notifications.
type targetErrObserver struct {
	mu     sync.Mutex
	stages []string
	errs   []error
}

func (o *targetErrObserver) OnCgroupsAttached(int) {}
func (o *targetErrObserver) OnCgroupsDetached(int) {}

func (o *targetErrObserver) OnTargetError(stage string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stages = append(o.stages, stage)
	o.errs = append(o.errs, err)
}

func (o *targetErrObserver) snapshot() ([]string, []error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.stages...), append([]error(nil), o.errs...)
}

// TestEngine_AttachFailureNotCountedAsExporter is the regression test for the
// misattributed-failure bug.
func TestEngine_AttachFailureNotCountedAsExporter(t *testing.T) {
	attachErr := errors.New("cgroup attach broken")
	backend := &mockBackend{setCgroupsErr: attachErr}
	obs := &targetErrObserver{}
	eng, err := tracer.NewEngine(
		backend,
		[]tracer.Exporter{&recordingExporter{name: "x"}},
		tracer.Config{Observer: obs},
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 1)
	targets <- tracer.TargetSet{{CgroupPath: "/will/fail", ContainerID: "c1"}}
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	waitUntil(t, 2*time.Second, func() bool { return eng.Stats().AttachFailure > 0 })

	s := eng.Stats()
	if s.ExporterFailure != 0 {
		t.Errorf("attach failure leaked into ExporterFailure=%d, want 0", s.ExporterFailure)
	}

	stages, errs := obs.snapshot()
	if len(stages) == 0 {
		t.Fatal("TargetErrorObserver was never notified of the attach failure")
	}
	if stages[0] != "set_cgroups" {
		t.Errorf("reported stage = %q, want set_cgroups", stages[0])
	}
	if !errors.Is(errs[0], attachErr) {
		t.Errorf("reported error = %v, want %v", errs[0], attachErr)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}
