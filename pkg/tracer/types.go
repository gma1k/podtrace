// Package tracer defines the stable boundary between podtrace's three
// operational modes (CLI, agent DaemonSet, session Job) and the eBPF
// tracing core implemented under internal/ebpf.
//
// The boundary is narrow on purpose:
//
//   - a Target describes one pod-level attachment site (cgroup + metadata),
//   - a TargetSet is the full set of sites the tracer should currently
//     attach to,
//   - an Exporter consumes events,
//   - an Engine orchestrates a TracerBackend over a stream of TargetSets
//     and dispatches events to a set of Exporters.
//
// Legacy CLI, agent, and job modes all drive the same Engine. They differ
// only in who produces the TargetSet stream (CLI: flags → informer,
// agent: PodTrace CR informer, job: flags derived from a
// PodTraceSession). The eBPF core and the Exporter implementations are
// identical across modes.
package tracer

import (
	"context"

	"github.com/podtrace/podtrace/internal/events"
)

// Target describes one pod whose traffic the tracer should observe. Each
// field is populated by the producer of the target stream (CLI target
// registry, CR-backed agent, or session Job) and is otherwise opaque to
// the Engine.
//
// The CgroupPath field is load-bearing: attachment is always cgroup-based.
// ContainerID and pod-level metadata are carried for exporter enrichment
// and for status reporting back to Kubernetes resources.
type Target struct {
	// PodName and Namespace identify the Kubernetes pod.
	PodName   string
	Namespace string

	// ContainerID is the short (CRI-normalized) container identifier.
	ContainerID string

	// ContainerName is the spec container name inside the pod.
	ContainerName string

	// CgroupPath is the absolute cgroup v2 path the eBPF program will be
	// attached to. Must be validated by the producer against the container
	// it is supposed to represent.
	CgroupPath string

	// Labels is a shallow copy of pod labels, used for exporter enrichment.
	// May be nil.
	Labels map[string]string

	// PodIP is the pod's primary IP at the time the target was resolved.
	// May be empty when the pod has not yet been assigned an address.
	PodIP string

	// OwnerKind / OwnerName identify the first controller owner reference
	// (Deployment, StatefulSet, DaemonSet, Job, …) — used for correlation
	// in exporters and in CR status.
	OwnerKind string
	OwnerName string
}

// TargetSet is the complete set of Targets the tracer should currently be
// attached to. It is the unit of update on the target stream: each tick
// of the stream is a full snapshot, not a delta. This is the simplest
// representation to reason about under concurrent producers (CRs merging
// with pod informers, for instance) and lets the tracer diff against
// prior state in one place.
type TargetSet []Target

// Exporter consumes events produced by the tracer core. Implementations
// must be safe for concurrent use by the Engine's dispatch loop.
//
// Close is called once, during Engine shutdown, and must release any
// network resources. Export must be non-blocking in the common case and
// should buffer internally; returning an error tells the Engine to count
// the events as dropped but not to stop the pipeline.
type Exporter interface {
	// Name returns a short, stable identifier for logging and metrics.
	Name() string

	// Export forwards a batch of events. Implementations must not retain
	// the slice beyond the call; callers may reuse the underlying array.
	Export(ctx context.Context, batch []*events.Event) error

	// Close flushes any pending exports and releases resources.
	Close(ctx context.Context) error
}

// TracerBackend is the minimal surface an Engine needs from the eBPF
// tracing core. internal/ebpf/tracer.TracerInterface satisfies it; an
// adapter is provided in this package.
type TracerBackend interface {
	// AttachToCgroup attaches eBPF programs to the given cgroup v2 path.
	// Idempotent — calling twice with the same path is a no-op.
	AttachToCgroup(cgroupPath string) error

	// SetContainerID associates the current attachment batch with a
	// container ID, used by the core for per-container filtering.
	SetContainerID(containerID string) error

	// Start begins streaming events into the supplied channel. Start must
	// return once the stream is wired; the long-lived work happens in
	// goroutines owned by the backend and terminates when ctx is done.
	Start(ctx context.Context, eventChan chan<- *events.Event) error

	// Stop flushes and detaches. Safe to call multiple times.
	Stop() error
}
