// Package tracer defines the stable boundary between podtrace's three
// operational modes (CLI, agent DaemonSet, session Job) and the eBPF
// tracing core implemented under internal/ebpf.
package tracer

import (
	"context"

	"github.com/podtrace/podtrace/internal/events"
)

// Target describes one pod whose traffic the tracer should observe.
type Target struct {
	PodName   string
	Namespace string

	ContainerID string

	ContainerName string

	ContainerPID uint32

	CgroupPath string

	Labels map[string]string

	PodIP string

	OwnerKind string
	OwnerName string
}

// TargetSet is the complete set of Targets the tracer should currently be
// attached to.
type TargetSet []Target

// Exporter consumes events produced by the tracer core. Implementations
// must be safe for concurrent use by the Engine's dispatch loop.
type Exporter interface {
	Name() string

	Export(ctx context.Context, batch []*events.Event) error

	Close(ctx context.Context) error
}

// CgroupTarget is one attachment site in a backend filter snapshot.
type CgroupTarget struct {
	CgroupPath  string
	ContainerID string
}

// TracerBackend is the minimal surface an Engine needs from the eBPF
// tracing core.
type TracerBackend interface {
	SetCgroups(targets []CgroupTarget) error

	AttachToCgroup(cgroupPath string) error

	SetContainerID(containerID string) error

	Start(ctx context.Context, eventChan chan<- *events.Event) error

	Stop() error
}

// EngineObserver is an optional hook the Engine notifies when the
// active target set changes.
type EngineObserver interface {
	OnCgroupsAttached(n int)
	OnCgroupsDetached(n int)
}

// TargetErrorObserver is an optional capability an EngineObserver may also
// implement.
type TargetErrorObserver interface {
	OnTargetError(stage string, err error)
}

// CategoryGateable is an optional capability a TracerBackend can
// implement to support kernel-side gating of probe groups by CRD
// filter category.
type CategoryGateable interface {
	SetEnabledCategories(categories []string) error
}

type ContainerUprobeTarget struct {
	ContainerID string
	PID         uint32
}

type ContainerUprobeReconciler interface {
	SetContainerTargets(targets []ContainerUprobeTarget) error
}
