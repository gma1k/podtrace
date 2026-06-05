package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	pkgkube "github.com/podtrace/podtrace/internal/kubernetes"
	"github.com/podtrace/podtrace/internal/kubernetes/nodespawn"
)

func TestFormatK8sEventsSection_Empty(t *testing.T) {
	if got := formatK8sEventsSection(nil); got != "" {
		t.Errorf("expected empty string for no groups, got %q", got)
	}
}

func TestFormatK8sEventsSection(t *testing.T) {
	base := time.Date(2026, 6, 5, 15, 11, 45, 0, time.UTC)
	groups := []podEvents{{
		pod: "o11y/web",
		events: []*pkgkube.K8sEvent{
			{Type: "Warning", Reason: "BackOff", Message: "back-off restarting", Timestamp: base.Add(10 * time.Second), Count: 3},
			{Type: "Normal", Reason: "Pulled", Message: "pulled image", Timestamp: base, Count: 1},
		},
	}}

	out := formatK8sEventsSection(groups)

	if !strings.Contains(out, "Kubernetes Events (observed during trace)") {
		t.Errorf("missing section header:\n%s", out)
	}
	if !strings.Contains(out, "o11y/web:") {
		t.Errorf("missing pod heading:\n%s", out)
	}
	if !strings.Contains(out, "(x3)") {
		t.Errorf("expected repeat count for BackOff:\n%s", out)
	}
	if strings.Index(out, "Pulled") > strings.Index(out, "BackOff") {
		t.Errorf("events not sorted chronologically:\n%s", out)
	}
}

func TestStartWorkstationEventCorrelation_NoopInputs(t *testing.T) {
	var buf bytes.Buffer

	startWorkstationEventCorrelation(context.Background(), nil, nil, &buf)()
	startWorkstationEventCorrelation(context.Background(), fake.NewSimpleClientset(), nil, &buf)()

	if buf.Len() != 0 {
		t.Errorf("expected no output for no-op inputs, got %q", buf.String())
	}
}

func TestStartWorkstationEventCorrelation_Forbidden(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	clientset.PrependWatchReactor("events", func(k8stesting.Action) (bool, watch.Interface, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "", Resource: "events"}, "", nil)
	})

	var buf bytes.Buffer
	finish := startWorkstationEventCorrelation(
		context.Background(),
		clientset,
		[]nodespawn.PodRef{{Namespace: "o11y", Name: "web"}},
		&buf,
	)
	finish()

	if buf.Len() != 0 {
		t.Errorf("expected no output when events watch is forbidden, got %q", buf.String())
	}
}
