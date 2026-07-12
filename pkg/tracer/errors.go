package tracer

import (
	"errors"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
)

// Backend startup error classes. These short, stable strings appear in:
//
//   - agent logs (`reason` field on the "tracer backend unavailable" line),
//   - `PodTrace.status.nodeStatus.message` (the operator's first stop),
//   - the `podtrace_agent_backend_degraded` metric reason label.
const (
	BackendErrUnknown          = "unknown"
	BackendErrPermission       = "permission_denied"
	BackendErrBTFUnavailable   = "btf_unavailable"
	BackendErrKernelTooOld     = "kernel_too_old"
	BackendErrVerifierRejected = "verifier_rejected"
	BackendErrCollection       = "collection_failed"
	BackendErrRingBuffer       = "ringbuf_failed"
	BackendErrMapLookup        = "map_lookup_failed"
	BackendErrInvalidEvent     = "invalid_event"
	BackendErrTracefsUnmounted = "tracefs_unmounted"
)

// ClassifyBackendError maps a backend startup error to one of the
// BackendErr* constants.
func ClassifyBackendError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	var verifierErr *ebpf.VerifierError
	if errors.As(err, &verifierErr) ||
		strings.Contains(msg, "verifier rejected") ||
		strings.Contains(msg, "verifier error") {
		return BackendErrVerifierRejected
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return BackendErrPermission
	}
	switch {
	case strings.Contains(msg, "permission denied"),
		strings.Contains(msg, "operation not permitted"):
		return BackendErrPermission
	case strings.Contains(msg, "tracefs"),
		strings.Contains(msg, "debugfs"):
		return BackendErrTracefsUnmounted
	case strings.Contains(msg, "btf"):
		return BackendErrBTFUnavailable
	case strings.Contains(msg, "ring buffer"),
		strings.Contains(msg, "ringbuf"):
		return BackendErrRingBuffer
	case strings.Contains(msg, "lookup map"):
		return BackendErrMapLookup
	case strings.Contains(msg, "invalid event"):
		return BackendErrInvalidEvent
	case strings.Contains(msg, "ebpf collection"),
		strings.Contains(msg, "create collection"):
		return BackendErrCollection
	}
	return BackendErrUnknown
}
