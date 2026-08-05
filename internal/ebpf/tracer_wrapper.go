package ebpf

import (
	"github.com/gma1k/podtrace/internal/ebpf/tracer"
)

type TracerInterface = tracer.TracerInterface

type ContainerProbeTarget = tracer.ContainerProbeTarget

func NewTracer() (TracerInterface, error) {
	return tracer.NewTracer()
}

func WaitForInterrupt() {
	tracer.WaitForInterrupt()
}

