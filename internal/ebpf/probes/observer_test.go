package probes

import (
	"errors"
	"sync"
	"testing"
)

type recordingObserver struct {
	mu      sync.Mutex
	entries []recordedAttachFailure
}

type recordedAttachFailure struct {
	program   string
	symbol    string
	mandatory bool
	err       error
}

func (r *recordingObserver) OnAttachFailure(program, symbol string, mandatory bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, recordedAttachFailure{program, symbol, mandatory, err})
}

func TestReportAttachFailure_NoObserver(t *testing.T) {
	SetAttachObserver(nil)
	defer SetAttachObserver(nil)
	reportAttachFailure("kprobe_x", "x", true, errors.New("boom"))
}

func TestReportAttachFailure_ForwardsToObserver(t *testing.T) {
	obs := &recordingObserver{}
	SetAttachObserver(obs)
	defer SetAttachObserver(nil)

	reportAttachFailure("kprobe_a", "sym_a", true, errors.New("mandatory bad"))
	reportAttachFailure("kprobe_b", "sym_b", false, errors.New("optional bad"))

	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(obs.entries))
	}
	if obs.entries[0].program != "kprobe_a" || !obs.entries[0].mandatory {
		t.Errorf("entry 0 = %+v", obs.entries[0])
	}
	if obs.entries[1].program != "kprobe_b" || obs.entries[1].mandatory {
		t.Errorf("entry 1 = %+v", obs.entries[1])
	}
}

func TestSetAttachObserver_ReplacesPrevious(t *testing.T) {
	first := &recordingObserver{}
	second := &recordingObserver{}
	SetAttachObserver(first)
	SetAttachObserver(second)
	defer SetAttachObserver(nil)

	reportAttachFailure("kprobe_x", "x", false, errors.New("e"))

	first.mu.Lock()
	defer first.mu.Unlock()
	second.mu.Lock()
	defer second.mu.Unlock()
	if len(first.entries) != 0 {
		t.Errorf("first observer should have been replaced; got %d entries", len(first.entries))
	}
	if len(second.entries) != 1 {
		t.Errorf("second observer entries = %d, want 1", len(second.entries))
	}
}