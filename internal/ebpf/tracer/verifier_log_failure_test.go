package tracer

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

func TestLogVerifierFailure_RealVerifierErrorLogsWithoutPanic(t *testing.T) {
	ve := &ebpf.VerifierError{
		Cause: fmt.Errorf("load rejected"),
		Log:   []string{"0: (b7) r1 = 1", "R1 invalid mem access"},
	}
	wrapped := fmt.Errorf("failed to create eBPF collection: %w", ve)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("logVerifierFailure panicked on a real verifier error: %v", r)
		}
	}()

	logVerifierFailure(ve)
	logVerifierFailure(wrapped)
}
