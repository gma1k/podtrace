package tracer

import (
	"errors"
	"testing"
)

func TestAFailedObjectLoadIsClassified(t *testing.T) {
	cases := []string{
		"failed to load eBPF program from internal/ebpf/embedded/podtrace.amd64.bpf.o: " +
			"open internal/ebpf/embedded/podtrace.amd64.bpf.o: no such file or directory",
		"failed to load BPF object: unexpected EOF",
	}
	for _, msg := range cases {
		if got := ClassifyBackendError(errors.New(msg)); got != BackendErrCollection {
			t.Errorf("ClassifyBackendError(%q) = %q, want %q. This is the likeliest real "+
				"failure — a bad build, a truncated object, an arch mismatch — and leaving it "+
				"unclassified puts reason=unknown on the one alert that should name itself",
				msg, got, BackendErrCollection)
		}
	}
}

func TestAnUnrecognisedErrorIsStillUnknown(t *testing.T) {
	if got := ClassifyBackendError(errors.New("something nobody predicted")); got != BackendErrUnknown {
		t.Errorf("got %q, want %q; over-broad matching would mislabel unrelated failures",
			got, BackendErrUnknown)
	}
}
