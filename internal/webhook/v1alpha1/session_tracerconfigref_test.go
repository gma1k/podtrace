package v1alpha1_test

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	webhookv1alpha1 "github.com/gma1k/podtrace/internal/webhook/v1alpha1"
)

func sessionWithTracerConfigRef(name string) *podtracev1alpha1.PodTraceSession {
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "sess", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    validSelector(),
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	if name != "" {
		s.Spec.TracerConfigRef = &podtracev1alpha1.LocalObjectReference{Name: name}
	}
	return s
}

func TestSessionTracerConfigRefUnsetIsValid(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp")
	v := &webhookv1alpha1.PodTraceSessionCustomValidator{Client: c}

	if _, err := v.ValidateCreate(context.Background(), sessionWithTracerConfigRef("")); err != nil {
		t.Errorf("an unset tracerConfigRef must be valid; it means resolve per node, got %v", err)
	}
}

func TestSessionTracerConfigRefAcceptsExistingConfig(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{ObjectMeta: metav1.ObjectMeta{Name: "regulated"}}
	c := newClientWithExporter(t, "default", "prod-otlp", tc)
	v := &webhookv1alpha1.PodTraceSessionCustomValidator{Client: c}

	if _, err := v.ValidateCreate(context.Background(), sessionWithTracerConfigRef("regulated")); err != nil {
		t.Errorf("a pin to an existing TracerConfig must be accepted, got %v", err)
	}
}

func TestSessionTracerConfigRefRejectsMissingConfig(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp")
	v := &webhookv1alpha1.PodTraceSessionCustomValidator{Client: c}

	_, err := v.ValidateCreate(context.Background(), sessionWithTracerConfigRef("ghost"))
	if err == nil {
		t.Fatal("a pin to a nonexistent TracerConfig would fail the session terminally at run time; reject it at apply")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error should name the missing config, got %q", err)
	}
	if !strings.Contains(err.Error(), "spec.tracerConfigRef") {
		t.Errorf("error should name the offending field, got %q", err)
	}
}

func TestSessionTracerConfigRefEmptyNameIsUnset(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp")
	v := &webhookv1alpha1.PodTraceSessionCustomValidator{Client: c}

	s := sessionWithTracerConfigRef("")
	s.Spec.TracerConfigRef = &podtracev1alpha1.LocalObjectReference{Name: ""}
	if _, err := v.ValidateCreate(context.Background(), s); err != nil {
		t.Errorf("an empty ref name must behave as unset rather than as a lookup for %q, got %v", "", err)
	}
}

func TestSessionTracerConfigRefCheckedOnUpdate(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp")
	v := &webhookv1alpha1.PodTraceSessionCustomValidator{Client: c}

	oldSession := sessionWithTracerConfigRef("")
	newSession := sessionWithTracerConfigRef("ghost")

	if _, err := v.ValidateUpdate(context.Background(), oldSession, newSession); err == nil {
		t.Fatal("adding a bad pin on update must be rejected too")
	}
}

func TestSessionTracerConfigRefSkippedWhenSpecUnchanged(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp")
	v := &webhookv1alpha1.PodTraceSessionCustomValidator{Client: c}

	stale := sessionWithTracerConfigRef("ghost")
	if _, err := v.ValidateUpdate(context.Background(), stale, stale.DeepCopy()); err != nil {
		t.Errorf("a metadata-only update must not re-validate the spec, or a session pinned to a since-deleted config could never be finalized: %v", err)
	}
}
