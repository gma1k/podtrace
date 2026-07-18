package v1alpha1_test

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	webhookv1alpha1 "github.com/podtrace/podtrace/internal/webhook/v1alpha1"
)

func grantNS(name, grant string) *corev1.Namespace {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if grant != "" {
		ns.Annotations = map[string]string{podtracev1alpha1.AllowTracingFromAnnotation: grant}
	}
	return ns
}

func TestPodTraceSessionValidator_CrossNamespaceGrant(t *testing.T) {
	cases := []struct {
		name      string
		podRefs   []podtracev1alpha1.PodRef
		nsObjects []client.Object
		wantError string
	}{
		{
			name:    "ungranted-cross-namespace-podref-rejected",
			podRefs: []podtracev1alpha1.PodRef{{Namespace: "team-b", Name: "victim"}},
			nsObjects: []client.Object{
				grantNS("team-b", ""),
			},
			wantError: `namespace "team-b" does not grant tracing to "default"`,
		},
		{
			name:      "missing-target-namespace-rejected-fail-closed",
			podRefs:   []podtracev1alpha1.PodRef{{Namespace: "ghost", Name: "victim"}},
			wantError: `namespace "ghost" does not grant tracing`,
		},
		{
			name:    "granted-cross-namespace-podref-allowed",
			podRefs: []podtracev1alpha1.PodRef{{Namespace: "team-b", Name: "pod"}},
			nsObjects: []client.Object{
				grantNS("team-b", "default"),
			},
			wantError: "",
		},
		{
			name:    "wildcard-grant-allowed",
			podRefs: []podtracev1alpha1.PodRef{{Namespace: "team-b", Name: "pod"}},
			nsObjects: []client.Object{
				grantNS("team-b", "*"),
			},
			wantError: "",
		},
		{
			name:      "own-namespace-podref-allowed",
			podRefs:   []podtracev1alpha1.PodRef{{Namespace: "default", Name: "pod"}},
			wantError: "",
		},
		{
			name:      "implicit-namespace-podref-allowed",
			podRefs:   []podtracev1alpha1.PodRef{{Name: "pod"}},
			wantError: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newClientWithExporter(t, "default", "prod-otlp", tc.nsObjects...)
			v := &webhookv1alpha1.PodTraceSessionCustomValidator{Client: c}
			obj := &podtracev1alpha1.PodTraceSession{
				ObjectMeta: metav1.ObjectMeta{Name: "pts", Namespace: "default"},
				Spec: podtracev1alpha1.PodTraceSessionSpec{
					PodRefs:     tc.podRefs,
					Duration:    metav1.Duration{Duration: 5 * time.Minute},
					ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
				},
			}
			_, err := v.ValidateCreate(context.Background(), obj)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantError)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("expected error to contain %q, got %q", tc.wantError, err.Error())
			}
		})
	}
}

func TestPodTraceSessionValidator_NamespaceSelectorGrantWarns(t *testing.T) {
	grantedProd := grantNS("granted", "default")
	grantedProd.Labels = map[string]string{"tier": "prod"}
	ungrantedProd := grantNS("ungranted", "")
	ungrantedProd.Labels = map[string]string{"tier": "prod"}

	c := newClientWithExporter(t, "default", "prod-otlp", grantedProd, ungrantedProd)
	v := &webhookv1alpha1.PodTraceSessionCustomValidator{Client: c}
	obj := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "pts", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:          &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "prod"}},
			Duration:          metav1.Duration{Duration: 5 * time.Minute},
			ExporterRef:       podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	warnings, err := v.ValidateCreate(context.Background(), obj)
	if err != nil {
		t.Fatalf("namespaceSelector grant gap must warn, not error: %v", err)
	}
	joined := strings.Join([]string(warnings), " ")
	if !strings.Contains(joined, "ungranted") {
		t.Errorf("expected warning naming the ungranted namespace, got %q", joined)
	}
	if strings.Contains(joined, "granted") && !strings.Contains(joined, "ungranted") {
		t.Errorf("granted namespace must not appear as ungranted: %q", joined)
	}
}

func TestPodTraceValidator_CrossNamespaceGrant(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp", grantNS("team-b", ""))
	v := &webhookv1alpha1.PodTraceCustomValidator{Client: c}
	obj := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSpec{
			PodRefs:     []podtracev1alpha1.PodRef{{Namespace: "team-b", Name: "victim"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	_, err := v.ValidateCreate(context.Background(), obj)
	if err == nil || !strings.Contains(err.Error(), "does not grant tracing") {
		t.Fatalf("expected cross-namespace grant rejection, got %v", err)
	}
}

func TestPodTraceScheduleValidator_CrossNamespaceGrant(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp", grantNS("team-b", ""))
	v := &webhookv1alpha1.PodTraceScheduleCustomValidator{Client: c}
	obj := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "sched", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule: "*/5 * * * *",
			SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
				Spec: podtracev1alpha1.PodTraceSessionSpec{
					PodRefs:     []podtracev1alpha1.PodRef{{Namespace: "team-b", Name: "victim"}},
					Duration:    metav1.Duration{Duration: 30 * time.Second},
					ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
				},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), obj)
	if err == nil || !strings.Contains(err.Error(), "does not grant tracing") {
		t.Fatalf("expected schedule template grant rejection, got %v", err)
	}
}
