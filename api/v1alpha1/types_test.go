package v1alpha1_test

import (
	"encoding/json"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// TestSchemeRegistration is a tripwire: if any of the root types or their
// List counterparts fall out of the scheme, controller-runtime's client
// will fail in obscure ways at runtime. Keep this asserting every kind —
// add new ones here as they are introduced.
func TestSchemeRegistration(t *testing.T) {
	s := runtime.NewScheme()
	if err := podtracev1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	want := []runtime.Object{
		&podtracev1alpha1.PodTrace{},
		&podtracev1alpha1.PodTraceList{},
		&podtracev1alpha1.PodTraceSession{},
		&podtracev1alpha1.PodTraceSessionList{},
		&podtracev1alpha1.ExporterConfig{},
		&podtracev1alpha1.ExporterConfigList{},
		&podtracev1alpha1.TracerConfig{},
		&podtracev1alpha1.TracerConfigList{},
		&podtracev1alpha1.PodTraceSchedule{},
		&podtracev1alpha1.PodTraceScheduleList{},
		&podtracev1alpha1.ApplicationTrace{},
		&podtracev1alpha1.ApplicationTraceList{},
	}
	for _, obj := range want {
		gvks, _, err := s.ObjectKinds(obj)
		if err != nil {
			t.Errorf("%T not registered: %v", obj, err)
			continue
		}
		if len(gvks) == 0 {
			t.Errorf("%T: no GVKs", obj)
			continue
		}
		if gvks[0].Group != "podtrace.io" || gvks[0].Version != "v1alpha1" {
			t.Errorf("%T: unexpected GVK %+v", obj, gvks[0])
		}
	}
}

// TestPodTraceRoundTrip asserts that the PodTrace type survives JSON
// encode/decode with all spec fields preserved. A silent DeepCopy bug or
// a missing json tag would show up here.
func TestPodTraceRoundTrip(t *testing.T) {
	samplePct := int32(50)
	orig := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Filters: []podtracev1alpha1.EventFilter{
				podtracev1alpha1.FilterDNS, podtracev1alpha1.FilterNet,
			},
			ExporterRef:   podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
			SamplePercent: &samplePct,
		},
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got podtracev1alpha1.PodTrace
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Name != "pt" || got.Namespace != "default" {
		t.Errorf("metadata lost: %+v", got.ObjectMeta)
	}
	if got.Spec.ExporterRef.Name != "prod-otlp" {
		t.Errorf("exporterRef.name lost: %q", got.Spec.ExporterRef.Name)
	}
	if got.Spec.SamplePercent == nil || *got.Spec.SamplePercent != 50 {
		t.Errorf("samplePercent lost: %+v", got.Spec.SamplePercent)
	}
	if len(got.Spec.Filters) != 2 || got.Spec.Filters[0] != podtracev1alpha1.FilterDNS {
		t.Errorf("filters lost: %+v", got.Spec.Filters)
	}
}

// TestPodTraceSessionDurationEncoded verifies that metav1.Duration
// survives JSON round-trip as a human-readable "5m" string rather than
// being serialized as a numeric value.
func TestPodTraceSessionDurationEncoded(t *testing.T) {
	orig := &podtracev1alpha1.PodTraceSession{
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Duration:    metav1.Duration{Duration: 5 * time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !containsSubstring(data, `"duration":"5m0s"`) {
		t.Errorf("duration not encoded as string in %s", data)
	}
}

func containsSubstring(data []byte, want string) bool {
	return len(data) > 0 && len(want) > 0 && indexOf(data, want) >= 0
}

func indexOf(data []byte, substr string) int {
	if len(substr) > len(data) {
		return -1
	}
	for i := 0; i <= len(data)-len(substr); i++ {
		match := true
		for j := range substr {
			if data[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// TestDeepCopyPreservesSpec catches the common bug where DeepCopy silently
// aliases slices or maps between the original and the copy.
func TestDeepCopyPreservesSpec(t *testing.T) {
	orig := &podtracev1alpha1.PodTrace{
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Filters:     []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterDNS},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	cp := orig.DeepCopy()
	// Mutate the copy's slices/maps — the original must not change.
	cp.Spec.Filters[0] = podtracev1alpha1.FilterNet
	cp.Spec.Selector.MatchLabels["app"] = "mutated"

	if orig.Spec.Filters[0] != podtracev1alpha1.FilterDNS {
		t.Errorf("filters aliased: orig=%v cp=%v", orig.Spec.Filters, cp.Spec.Filters)
	}
	if orig.Spec.Selector.MatchLabels["app"] != "api" {
		t.Errorf("selector.matchLabels aliased: orig=%v cp=%v", orig.Spec.Selector.MatchLabels, cp.Spec.Selector.MatchLabels)
	}
}
