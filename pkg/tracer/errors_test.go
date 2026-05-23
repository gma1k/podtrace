package tracer

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestClassifyBackendError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"eacces", syscall.EACCES, BackendErrPermission},
		{"eperm", syscall.EPERM, BackendErrPermission},
		{"wrapped eacces", fmt.Errorf("load program: %w", syscall.EACCES), BackendErrPermission},
		{"permission denied phrase", errors.New("bpf(BPF_PROG_LOAD): permission denied"), BackendErrPermission},
		{"operation not permitted phrase", errors.New("operation not permitted"), BackendErrPermission},
		{"tracefs unmounted", errors.New("neither debugfs nor tracefs are mounted"), BackendErrTracefsUnmounted},
		{"tracefs only", errors.New("tracefs not mounted at /sys/kernel/tracing"), BackendErrTracefsUnmounted},
		{"btf unavailable", errors.New("kernel BTF not available"), BackendErrBTFUnavailable},
		{"btf lower", errors.New("btf unsupported on this kernel"), BackendErrBTFUnavailable},
		{"verifier rejected", errors.New("program load: verifier rejected program: invalid stack access"), BackendErrKernelTooOld},
		{"verifier error", errors.New("verifier error: too many instructions"), BackendErrKernelTooOld},
		{"ringbuf", errors.New("ringbuf reader: bad fd"), BackendErrRingBuffer},
		{"ring buffer phrase", errors.New("create ring buffer: ENOMEM"), BackendErrRingBuffer},
		{"map lookup", errors.New("lookup map filter_cgroups: ENOENT"), BackendErrMapLookup},
		{"invalid event", errors.New("invalid event: short read"), BackendErrInvalidEvent},
		{"collection failed", errors.New("create ebpf collection: program too large"), BackendErrCollection},
		{"unknown", errors.New("something unexpected"), BackendErrUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyBackendError(c.err); got != c.want {
				t.Errorf("ClassifyBackendError(%v) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}
