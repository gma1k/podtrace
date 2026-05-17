package tracer

import (
	"context"

	"github.com/podtrace/podtrace/internal/events"
)

type TracerInterface interface {
	SetCgroups(cgroupPaths []string) error

	AttachToCgroup(cgroupPath string) error
	SetContainerID(containerID string) error
	Start(ctx context.Context, eventChan chan<- *events.Event) error
	Stop() error
}

