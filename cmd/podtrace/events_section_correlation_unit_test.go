package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/podtrace/podtrace/internal/kubernetes/nodespawn"
)

func TestStartWorkstationEventCorrelation_NilClientsetIsNoop(t *testing.T) {
	finish := startWorkstationEventCorrelation(context.Background(), nil,
		[]nodespawn.PodRef{{Namespace: "ns", Name: "a"}}, &bytes.Buffer{})
	finish()
}

func TestStartWorkstationEventCorrelation_EmptyPodsIsNoop(t *testing.T) {
	finish := startWorkstationEventCorrelation(context.Background(),
		fake.NewSimpleClientset(), nil, &bytes.Buffer{})
	finish()
}

func TestStartWorkstationEventCorrelation_DeduplicatesAndStarts(t *testing.T) {
	cs := fake.NewSimpleClientset()
	pods := []nodespawn.PodRef{
		{Namespace: "ns", Name: "a"},
		{Namespace: "ns", Name: "a"},
		{Namespace: "ns", Name: "b"},
		{Namespace: "ns", Name: ""},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var buf bytes.Buffer
	finish := startWorkstationEventCorrelation(ctx, cs, pods, &buf)

	finish()

	if buf.Len() != 0 {
		t.Fatalf("expected no event section for an empty fake cluster, got %q", buf.String())
	}
}
