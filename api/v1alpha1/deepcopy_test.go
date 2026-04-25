package v1alpha1

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// populated*() builders return fully-populated values whose generated
// DeepCopy* code paths must walk every field, slice, map, and pointer
// branch. The exact field values are arbitrary — what matters is that
// the round-trip produces a structurally-equal but pointer-distinct
// copy.

func populatedPodTrace() *PodTrace {
	tt := metav1.NewTime(metav1.Now().Time)
	rate := int32(50)
	return &PodTrace{
		TypeMeta: metav1.TypeMeta{Kind: "PodTrace", APIVersion: "podtrace.io/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pt", Namespace: "ns",
			Labels:      map[string]string{"l": "1"},
			Annotations: map[string]string{"a": "1"},
		},
		Spec: PodTraceSpec{
			Selector:          &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			PodRefs:           []PodRef{{Name: "p", Namespace: "n"}},
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}},
			ContainerName:     "c0",
			Filters:           []EventFilter{FilterDNS, FilterNet},
			ExporterRef:       LocalObjectReference{Name: "ec"},
			Thresholds: &Thresholds{
				ErrorRatePercent: ptrI32(5),
				RTTSpikeMs:       ptrI32(100),
				FSSlowMs:         ptrI32(50),
			},
			SamplePercent: &rate,
			Paused:        true,
		},
		Status: PodTraceStatus{
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue, LastTransitionTime: tt},
			},
			NodeStatus: []PodTraceNodeStatus{
				{Node: "n1", Ready: true, ActiveCgroups: 2, EventsTotal: 100, LastHeartbeat: tt},
			},
			MatchedPods:        2,
			ObservedGeneration: 7,
		},
	}
}

func populatedPodTraceSession() *PodTraceSession {
	tt := metav1.NewTime(metav1.Now().Time)
	ttl := int32(300)
	rate := int32(25)
	return &PodTraceSession{
		TypeMeta: metav1.TypeMeta{Kind: "PodTraceSession", APIVersion: "podtrace.io/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "s", Namespace: "ns",
			Labels: map[string]string{"l": "1"},
		},
		Spec: PodTraceSessionSpec{
			Selector:                &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			PodRefs:                 []PodRef{{Name: "p1"}, {Name: "p2", Namespace: "other"}},
			NamespaceSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}},
			Duration:                metav1.Duration{Duration: 60_000_000_000}, // 60s
			Filters:                 []EventFilter{FilterFS, FilterCPU},
			ExporterRef:             LocalObjectReference{Name: "ec"},
			Thresholds:              &Thresholds{ErrorRatePercent: ptrI32(10)},
			SamplePercent:           &rate,
			ReportRef: &ReportReference{
				ConfigMap:   &corev1.LocalObjectReference{Name: "cm"},
				Secret:      &corev1.LocalObjectReference{Name: "sec"},
				ObjectStore: &ObjectStoreReference{CredentialsSecretRef: &corev1.LocalObjectReference{Name: "store"}},
			},
			TTLSecondsAfterFinished: &ttl,
		},
		Status: PodTraceSessionStatus{
			Phase:          SessionPhaseRunning,
			StartTime:      &tt,
			CompletionTime: &tt,
			Jobs: []SessionJobRef{
				{Node: "n1", Name: "j1", Completed: true, EventCount: 10, StartTime: &tt, CompletionTime: &tt, Message: "ok"},
			},
			Summary: &SessionSummary{TotalEvents: 10, DNSEvents: 4, ErrorsDetected: 1},
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue, LastTransitionTime: tt},
			},
		},
	}
}

func populatedTracerConfig() *TracerConfig {
	d := metav1.Duration{Duration: 1_000_000_000}
	ttl := int32(900)
	bl := int32(2)
	return &TracerConfig{
		TypeMeta:   metav1.TypeMeta{Kind: "TracerConfig", APIVersion: "podtrace.io/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: TracerConfigSpec{
			Image:            "img",
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}},
			Agent: AgentSpec{
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU: resource.MustParse("100m"),
					},
				},
				StatusReportInterval: &d,
			},
			Session: SessionRuntimeSpec{
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse("64Mi"),
					},
				},
				TTLSecondsAfterFinished: &ttl,
				BackoffLimit:            &bl,
				MaxDuration:             &d,
			},
			NodeSelector:    map[string]string{"role": "trace"},
			Tolerations:     []corev1.Toleration{{Key: "k", Operator: corev1.TolerationOpEqual, Value: "v"}},
			Affinity:        &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{}},
			SystemNamespace: "podtrace-system",
		},
		Status: TracerConfigStatus{
			Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}},
		},
	}
}

func populatedExporterConfig() *ExporterConfig {
	rate := int32(100)
	return &ExporterConfig{
		TypeMeta: metav1.TypeMeta{Kind: "ExporterConfig", APIVersion: "podtrace.io/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "ns"},
		Spec: ExporterConfigSpec{
			Type: ExporterTypeOTLP,
			OTLP: &OTLPExporter{
				Endpoint: "otel:4318",
				Protocol: OTLPProtocolHTTP,
				Insecure: true,
				Headers: []OTLPHeader{
					{Name: "X-Env", Value: "prod"},
					{Name: "Auth", ValueFrom: &SecretKeySelector{Name: "sec", Key: "tok"}},
				},
				HeadersFromSecret: &LocalObjectReference{Name: "h"},
			},
			Jaeger:        &JaegerExporter{Endpoint: "j"},
			Zipkin:        &ZipkinExporter{Endpoint: "z"},
			Splunk:        &SplunkExporter{Endpoint: "s", TokenSecretRef: SecretKeySelector{Name: "tok", Key: "k"}},
			DataDog:       &DataDogExporter{Site: "datadoghq.eu", APIKeySecretRef: SecretKeySelector{Name: "dd", Key: "k"}},
			SamplePercent: &rate,
		},
		Status: ExporterConfigStatus{
			Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}},
		},
	}
}

func ptrI32(v int32) *int32 { return &v }

// assertDeepCopyOK checks the round-trip property that a DeepCopy is
// (a) deeply equal to the source and (b) pointer-distinct so mutations
// do not bleed back. Used as the workhorse for every type below.
func assertDeepCopyOK(t *testing.T, src, copyOut interface{}) {
	t.Helper()
	if !reflect.DeepEqual(src, copyOut) {
		t.Errorf("DeepCopy result not equal to source\nsrc=%#v\ncpy=%#v", src, copyOut)
	}
	if reflect.ValueOf(src).Pointer() == reflect.ValueOf(copyOut).Pointer() {
		t.Error("DeepCopy returned the same pointer (alias, not copy)")
	}
}

// ─── nil-safety: every DeepCopy must return nil when receiver is nil.
func TestDeepCopy_NilSafety(t *testing.T) {
	if (*PodTrace)(nil).DeepCopy() != nil {
		t.Error("PodTrace nil DeepCopy")
	}
	if (*PodTraceList)(nil).DeepCopy() != nil {
		t.Error("PodTraceList nil DeepCopy")
	}
	if (*PodTraceSpec)(nil).DeepCopy() != nil {
		t.Error("PodTraceSpec nil DeepCopy")
	}
	if (*PodTraceStatus)(nil).DeepCopy() != nil {
		t.Error("PodTraceStatus nil DeepCopy")
	}
	if (*PodTraceNodeStatus)(nil).DeepCopy() != nil {
		t.Error("PodTraceNodeStatus nil DeepCopy")
	}
	if (*PodTraceSession)(nil).DeepCopy() != nil {
		t.Error("PodTraceSession nil DeepCopy")
	}
	if (*PodTraceSessionList)(nil).DeepCopy() != nil {
		t.Error("PodTraceSessionList nil DeepCopy")
	}
	if (*PodTraceSessionSpec)(nil).DeepCopy() != nil {
		t.Error("PodTraceSessionSpec nil DeepCopy")
	}
	if (*PodTraceSessionStatus)(nil).DeepCopy() != nil {
		t.Error("PodTraceSessionStatus nil DeepCopy")
	}
	if (*ExporterConfig)(nil).DeepCopy() != nil {
		t.Error("ExporterConfig nil DeepCopy")
	}
	if (*ExporterConfigList)(nil).DeepCopy() != nil {
		t.Error("ExporterConfigList nil DeepCopy")
	}
	if (*ExporterConfigSpec)(nil).DeepCopy() != nil {
		t.Error("ExporterConfigSpec nil DeepCopy")
	}
	if (*ExporterConfigStatus)(nil).DeepCopy() != nil {
		t.Error("ExporterConfigStatus nil DeepCopy")
	}
	if (*OTLPExporter)(nil).DeepCopy() != nil {
		t.Error("OTLPExporter nil DeepCopy")
	}
	if (*OTLPHeader)(nil).DeepCopy() != nil {
		t.Error("OTLPHeader nil DeepCopy")
	}
	if (*JaegerExporter)(nil).DeepCopy() != nil {
		t.Error("JaegerExporter nil DeepCopy")
	}
	if (*ZipkinExporter)(nil).DeepCopy() != nil {
		t.Error("ZipkinExporter nil DeepCopy")
	}
	if (*SplunkExporter)(nil).DeepCopy() != nil {
		t.Error("SplunkExporter nil DeepCopy")
	}
	if (*DataDogExporter)(nil).DeepCopy() != nil {
		t.Error("DataDogExporter nil DeepCopy")
	}
	if (*TracerConfig)(nil).DeepCopy() != nil {
		t.Error("TracerConfig nil DeepCopy")
	}
	if (*TracerConfigList)(nil).DeepCopy() != nil {
		t.Error("TracerConfigList nil DeepCopy")
	}
	if (*TracerConfigSpec)(nil).DeepCopy() != nil {
		t.Error("TracerConfigSpec nil DeepCopy")
	}
	if (*TracerConfigStatus)(nil).DeepCopy() != nil {
		t.Error("TracerConfigStatus nil DeepCopy")
	}
	if (*AgentSpec)(nil).DeepCopy() != nil {
		t.Error("AgentSpec nil DeepCopy")
	}
	if (*SessionRuntimeSpec)(nil).DeepCopy() != nil {
		t.Error("SessionRuntimeSpec nil DeepCopy")
	}
	if (*SessionJobRef)(nil).DeepCopy() != nil {
		t.Error("SessionJobRef nil DeepCopy")
	}
	if (*SessionSummary)(nil).DeepCopy() != nil {
		t.Error("SessionSummary nil DeepCopy")
	}
	if (*Thresholds)(nil).DeepCopy() != nil {
		t.Error("Thresholds nil DeepCopy")
	}
	if (*PodRef)(nil).DeepCopy() != nil {
		t.Error("PodRef nil DeepCopy")
	}
	if (*ReportReference)(nil).DeepCopy() != nil {
		t.Error("ReportReference nil DeepCopy")
	}
	if (*ObjectStoreReference)(nil).DeepCopy() != nil {
		t.Error("ObjectStoreReference nil DeepCopy")
	}
	if (*LocalObjectReference)(nil).DeepCopy() != nil {
		t.Error("LocalObjectReference nil DeepCopy")
	}
	if (*SecretKeySelector)(nil).DeepCopy() != nil {
		t.Error("SecretKeySelector nil DeepCopy")
	}
	if (*PodTraceCustomValidator)(nil).DeepCopy() != nil {
		t.Error("PodTraceCustomValidator nil DeepCopy")
	}
	if (*PodTraceSessionCustomValidator)(nil).DeepCopy() != nil {
		t.Error("PodTraceSessionCustomValidator nil DeepCopy")
	}
	if (*ExporterConfigCustomValidator)(nil).DeepCopy() != nil {
		t.Error("ExporterConfigCustomValidator nil DeepCopy")
	}
}

// ─── Round-trip equality, fully-populated values (covers every branch).
func TestDeepCopy_PodTraceRoundTrip(t *testing.T) {
	src := populatedPodTrace()
	cp := src.DeepCopy()
	assertDeepCopyOK(t, src, cp)

	// Mutate the copy to assert no aliasing.
	cp.Spec.Selector.MatchLabels["app"] = "MUTATED"
	if src.Spec.Selector.MatchLabels["app"] == "MUTATED" {
		t.Fatal("Selector aliased through DeepCopy")
	}
	cp.Status.NodeStatus[0].Node = "MUTATED"
	if src.Status.NodeStatus[0].Node == "MUTATED" {
		t.Fatal("NodeStatus slice aliased")
	}
	cp.Spec.Filters[0] = "MUTATED"
	if src.Spec.Filters[0] == "MUTATED" {
		t.Fatal("Filters slice aliased")
	}
}

func TestDeepCopy_PodTraceList(t *testing.T) {
	src := &PodTraceList{
		TypeMeta: metav1.TypeMeta{Kind: "PodTraceList"},
		ListMeta: metav1.ListMeta{ResourceVersion: "1"},
		Items:    []PodTrace{*populatedPodTrace()},
	}
	cp := src.DeepCopy()
	assertDeepCopyOK(t, src, cp)
	cp.Items[0].Spec.ContainerName = "MUTATED"
	if src.Items[0].Spec.ContainerName == "MUTATED" {
		t.Fatal("Items aliased")
	}
}

func TestDeepCopy_PodTraceSessionRoundTrip(t *testing.T) {
	src := populatedPodTraceSession()
	cp := src.DeepCopy()
	assertDeepCopyOK(t, src, cp)
}

func TestDeepCopy_PodTraceSessionList(t *testing.T) {
	src := &PodTraceSessionList{
		Items: []PodTraceSession{*populatedPodTraceSession()},
	}
	cp := src.DeepCopy()
	assertDeepCopyOK(t, src, cp)
}

func TestDeepCopy_TracerConfigRoundTrip(t *testing.T) {
	src := populatedTracerConfig()
	cp := src.DeepCopy()
	assertDeepCopyOK(t, src, cp)
}

func TestDeepCopy_TracerConfigList(t *testing.T) {
	src := &TracerConfigList{
		Items: []TracerConfig{*populatedTracerConfig()},
	}
	cp := src.DeepCopy()
	assertDeepCopyOK(t, src, cp)
}

func TestDeepCopy_ExporterConfigRoundTrip(t *testing.T) {
	src := populatedExporterConfig()
	cp := src.DeepCopy()
	assertDeepCopyOK(t, src, cp)
}

func TestDeepCopy_ExporterConfigList(t *testing.T) {
	src := &ExporterConfigList{
		Items: []ExporterConfig{*populatedExporterConfig()},
	}
	cp := src.DeepCopy()
	assertDeepCopyOK(t, src, cp)
}

// ─── DeepCopyObject (root types only): the runtime.Object surface.
func TestDeepCopyObject_RootKinds(t *testing.T) {
	cases := []runtime.Object{
		populatedPodTrace(),
		&PodTraceList{Items: []PodTrace{*populatedPodTrace()}},
		populatedPodTraceSession(),
		&PodTraceSessionList{Items: []PodTraceSession{*populatedPodTraceSession()}},
		populatedExporterConfig(),
		&ExporterConfigList{Items: []ExporterConfig{*populatedExporterConfig()}},
		populatedTracerConfig(),
		&TracerConfigList{Items: []TracerConfig{*populatedTracerConfig()}},
	}
	for _, src := range cases {
		cp := src.DeepCopyObject()
		if cp == nil {
			t.Errorf("%T DeepCopyObject returned nil", src)
			continue
		}
		if reflect.TypeOf(cp) != reflect.TypeOf(src) {
			t.Errorf("%T: copy type %T does not match source", src, cp)
		}
	}
}

func TestDeepCopyObject_NilReceiverReturnsNilObject(t *testing.T) {
	// Concrete-typed nil pointers: DeepCopyObject must return an
	// interface holding nil (as the codegen guard returns nil when the
	// inner DeepCopy yields nil).
	if (*PodTrace)(nil).DeepCopyObject() != nil {
		t.Error("PodTrace nil DeepCopyObject")
	}
	if (*PodTraceList)(nil).DeepCopyObject() != nil {
		t.Error("PodTraceList nil DeepCopyObject")
	}
	if (*PodTraceSession)(nil).DeepCopyObject() != nil {
		t.Error("PodTraceSession nil DeepCopyObject")
	}
	if (*PodTraceSessionList)(nil).DeepCopyObject() != nil {
		t.Error("PodTraceSessionList nil DeepCopyObject")
	}
	if (*ExporterConfig)(nil).DeepCopyObject() != nil {
		t.Error("ExporterConfig nil DeepCopyObject")
	}
	if (*ExporterConfigList)(nil).DeepCopyObject() != nil {
		t.Error("ExporterConfigList nil DeepCopyObject")
	}
	if (*TracerConfig)(nil).DeepCopyObject() != nil {
		t.Error("TracerConfig nil DeepCopyObject")
	}
	if (*TracerConfigList)(nil).DeepCopyObject() != nil {
		t.Error("TracerConfigList nil DeepCopyObject")
	}
}

// ─── Smaller leaf types — exercise DeepCopyInto branches missed by the
//     populatedX builders (mostly sparse/nil-pointer combinations).
func TestDeepCopy_LeafTypes(t *testing.T) {
	t.Run("OTLPHeader literal vs ValueFrom", func(t *testing.T) {
		lit := OTLPHeader{Name: "X", Value: "v"}
		cp := lit.DeepCopy()
		if !reflect.DeepEqual(&lit, cp) {
			t.Fatal("literal header round-trip")
		}
		ref := OTLPHeader{Name: "Auth", ValueFrom: &SecretKeySelector{Name: "s", Key: "k"}}
		cp2 := ref.DeepCopy()
		if !reflect.DeepEqual(&ref, cp2) {
			t.Fatal("ref header round-trip")
		}
		cp2.ValueFrom.Name = "MUT"
		if ref.ValueFrom.Name == "MUT" {
			t.Fatal("ValueFrom aliased")
		}
	})

	t.Run("Thresholds with nil pointers", func(t *testing.T) {
		empty := Thresholds{}
		cp := empty.DeepCopy()
		if !reflect.DeepEqual(&empty, cp) {
			t.Fatal("empty Thresholds round-trip")
		}
	})

	t.Run("ReportReference with one-of variants", func(t *testing.T) {
		cm := &ReportReference{ConfigMap: &corev1.LocalObjectReference{Name: "cm"}}
		cp := cm.DeepCopy()
		assertDeepCopyOK(t, cm, cp)

		sec := &ReportReference{Secret: &corev1.LocalObjectReference{Name: "s"}}
		cp = sec.DeepCopy()
		assertDeepCopyOK(t, sec, cp)

		os := &ReportReference{ObjectStore: &ObjectStoreReference{URI: "s3://b/path"}}
		cp = os.DeepCopy()
		assertDeepCopyOK(t, os, cp)
	})

	t.Run("ExporterConfigSpec sparse variants", func(t *testing.T) {
		// Each exporter type alone — exercises the if-non-nil branches.
		s := ExporterConfigSpec{Type: ExporterTypeJaeger, Jaeger: &JaegerExporter{Endpoint: "j"}}
		cp := s.DeepCopy()
		if !reflect.DeepEqual(&s, cp) {
			t.Fatal("Jaeger-only round-trip")
		}
		s = ExporterConfigSpec{Type: ExporterTypeZipkin, Zipkin: &ZipkinExporter{Endpoint: "z"}}
		cp = s.DeepCopy()
		if !reflect.DeepEqual(&s, cp) {
			t.Fatal("Zipkin-only round-trip")
		}
		s = ExporterConfigSpec{Type: ExporterTypeSplunk, Splunk: &SplunkExporter{Endpoint: "s"}}
		cp = s.DeepCopy()
		if !reflect.DeepEqual(&s, cp) {
			t.Fatal("Splunk-only round-trip")
		}
		s = ExporterConfigSpec{Type: ExporterTypeDataDog, DataDog: &DataDogExporter{Site: "d"}}
		cp = s.DeepCopy()
		if !reflect.DeepEqual(&s, cp) {
			t.Fatal("DataDog-only round-trip")
		}
	})

	t.Run("AgentSpec/SessionRuntimeSpec nil-pointer paths", func(t *testing.T) {
		a := AgentSpec{LogLevel: "info"}
		cp := a.DeepCopy()
		if !reflect.DeepEqual(&a, cp) {
			t.Fatal("AgentSpec round-trip")
		}
		s := SessionRuntimeSpec{}
		cps := s.DeepCopy()
		if !reflect.DeepEqual(&s, cps) {
			t.Fatal("SessionRuntimeSpec round-trip")
		}
	})

	t.Run("SessionJobRef with nil times", func(t *testing.T) {
		j := SessionJobRef{Node: "n", Name: "j"}
		cp := j.DeepCopy()
		if !reflect.DeepEqual(&j, cp) {
			t.Fatal("SessionJobRef round-trip")
		}
	})

	t.Run("Scalar wrappers", func(t *testing.T) {
		_ = (&PodRef{Name: "p"}).DeepCopy()
		_ = (&LocalObjectReference{Name: "l"}).DeepCopy()
		_ = (&SecretKeySelector{Name: "s", Key: "k"}).DeepCopy()
		_ = (&SessionSummary{TotalEvents: 1}).DeepCopy()
		_ = (&PodTraceNodeStatus{Node: "n"}).DeepCopy()
		_ = (&JaegerExporter{Endpoint: "j"}).DeepCopy()
		_ = (&ZipkinExporter{Endpoint: "z"}).DeepCopy()
		_ = (&DataDogExporter{Site: "x"}).DeepCopy()
		_ = (&SplunkExporter{Endpoint: "x"}).DeepCopy()
		_ = (&PodTraceCustomValidator{}).DeepCopy()
		_ = (&PodTraceSessionCustomValidator{}).DeepCopy()
		_ = (&ExporterConfigCustomValidator{}).DeepCopy()
	})
}

// ─── groupversion_info ───────────────────────────────────────────────

func TestResource_QualifiesWithGroup(t *testing.T) {
	got := Resource("podtraces")
	if got.Group != "podtrace.io" || got.Resource != "podtraces" {
		t.Errorf("got %+v, want {Group: podtrace.io, Resource: podtraces}", got)
	}
}
