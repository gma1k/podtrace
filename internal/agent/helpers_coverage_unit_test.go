package agent

import (
	"math"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// attrMap flattens an OTel attribute slice into a string-keyed lookup
// for order-independent assertions.
func attrMap(attrs []attribute.KeyValue) map[string]attribute.Value {
	out := make(map[string]attribute.Value, len(attrs))
	for _, kv := range attrs {
		out[string(kv.Key)] = kv.Value
	}
	return out
}

// TestAppendK8sAttributes_NilAndZero covers the short-circuit branches:
// a nil bundle and an all-empty bundle must both return attrs untouched.
func TestAppendK8sAttributes_NilAndZero(t *testing.T) {
	base := []attribute.KeyValue{attribute.String("pre", "existing")}

	if got := appendK8sAttributes(base, nil); len(got) != len(base) {
		t.Errorf("nil meta: len=%d, want %d (unchanged)", len(got), len(base))
	}

	zero := &events.K8sMetadata{}
	if got := appendK8sAttributes(base, zero); len(got) != len(base) {
		t.Errorf("zero meta: len=%d, want %d (unchanged)", len(got), len(base))
	}
}

// TestAppendK8sAttributes_FullBundle asserts every populated field maps
// to its semconv key, including the Deployment workload branch.
func TestAppendK8sAttributes_FullBundle(t *testing.T) {
	meta := &events.K8sMetadata{
		Namespace:     "team-a",
		PodName:       "web-abc",
		PodUID:        "uid-123",
		NodeName:      "node-1",
		ContainerName: "app",
		WorkloadKind:  "Deployment",
		WorkloadName:  "web",
	}

	m := attrMap(appendK8sAttributes(nil, meta))

	want := map[string]string{
		"k8s.namespace.name":  "team-a",
		"k8s.pod.name":        "web-abc",
		"k8s.pod.uid":         "uid-123",
		"k8s.node.name":       "node-1",
		"k8s.container.name":  "app",
		"k8s.deployment.name": "web",
	}
	for key, val := range want {
		got, ok := m[key]
		if !ok {
			t.Errorf("missing attribute %q", key)
			continue
		}
		if got.AsString() != val {
			t.Errorf("attribute %q = %q, want %q", key, got.AsString(), val)
		}
	}
}

// TestAppendK8sAttributes_WorkloadKinds exercises the appendWorkloadAttributes
// switch: each known kind maps to its specific semconv key, an unknown
// kind falls through to the generic k8s.workload.* pair, and the
// Pod/empty kinds emit nothing.
func TestAppendK8sAttributes_WorkloadKinds(t *testing.T) {
	cases := []struct {
		kind    string
		wantKey string
	}{
		{"StatefulSet", "k8s.statefulset.name"},
		{"DaemonSet", "k8s.daemonset.name"},
		{"Job", "k8s.job.name"},
		{"CronJob", "k8s.cronjob.name"},
		{"ReplicaSet", "k8s.replicaset.name"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			meta := &events.K8sMetadata{WorkloadKind: tc.kind, WorkloadName: "wl"}
			m := attrMap(appendK8sAttributes(nil, meta))
			if v, ok := m[tc.wantKey]; !ok || v.AsString() != "wl" {
				t.Errorf("kind %q: missing/incorrect %q (got %v ok=%v)", tc.kind, tc.wantKey, v, ok)
			}
		})
	}

	unknown := &events.K8sMetadata{WorkloadKind: "Rollout", WorkloadName: "argo"}
	m := attrMap(appendK8sAttributes(nil, unknown))
	if v, ok := m["k8s.workload.kind"]; !ok || v.AsString() != "Rollout" {
		t.Errorf("unknown kind: k8s.workload.kind missing/incorrect (got %v ok=%v)", v, ok)
	}
	if v, ok := m["k8s.workload.name"]; !ok || v.AsString() != "argo" {
		t.Errorf("unknown kind: k8s.workload.name missing/incorrect (got %v ok=%v)", v, ok)
	}

	pod := &events.K8sMetadata{WorkloadKind: "Pod", WorkloadName: "standalone"}
	pm := attrMap(appendK8sAttributes(nil, pod))
	for _, k := range []string{"k8s.workload.kind", "k8s.workload.name", "k8s.deployment.name"} {
		if _, ok := pm[k]; ok {
			t.Errorf("Pod kind unexpectedly emitted %q", k)
		}
	}
}

// TestLenToInt32_NegativeAndOverflow covers the two clamp branches not
// already exercised by TestLenToInt32: negative -> 0 and >MaxInt32 ->
// MaxInt32.
func TestLenToInt32_NegativeAndOverflow(t *testing.T) {
	if got := lenToInt32(-5); got != 0 {
		t.Errorf("negative input: got %d, want 0", got)
	}
	if got := lenToInt32(math.MaxInt32); got != math.MaxInt32 {
		t.Errorf("at-max input: got %d, want %d", got, int32(math.MaxInt32))
	}
	if math.MaxInt > math.MaxInt32 {
		if got := lenToInt32(math.MaxInt32 + 1); got != math.MaxInt32 {
			t.Errorf("overflow input: got %d, want %d", got, int32(math.MaxInt32))
		}
	}
}

// TestRecordThresholdTripped covers the Metrics recorder and its nil
// short-circuit. The counter must increment once per call, per label set.
func TestRecordThresholdTripped(t *testing.T) {
	// Nil receiver must not panic.
	var nilM *Metrics
	nilM.RecordThresholdTripped(CRKey{"ns", "cr"}, "fs_slow")

	m := NewMetrics()
	cr := CRKey{Namespace: "ns", Name: "cr"}

	m.RecordThresholdTripped(cr, "fs_slow")
	m.RecordThresholdTripped(cr, "fs_slow")
	m.RecordThresholdTripped(cr, "rtt_spike")

	if got := counterValue(t, m.ThresholdTripped, map[string]string{
		"cr_namespace": "ns", "cr_name": "cr", "threshold": "fs_slow",
	}); got != 2 {
		t.Errorf("fs_slow counter = %v, want 2", got)
	}
	if got := counterValue(t, m.ThresholdTripped, map[string]string{
		"cr_namespace": "ns", "cr_name": "cr", "threshold": "rtt_spike",
	}); got != 1 {
		t.Errorf("rtt_spike counter = %v, want 1", got)
	}
}

// TestSDKEventExporter_RecordTrip covers recordTrip: it delegates to the
// metrics recorder when metrics is set, and is a no-op when nil.
func TestSDKEventExporter_RecordTrip(t *testing.T) {
	(&sdkEventExporter{cr: CRKey{"ns", "cr"}}).recordTrip("error_rate")

	m := NewMetrics()
	cr := CRKey{Namespace: "ns", Name: "cr"}
	exp := &sdkEventExporter{cr: cr, metrics: m}

	exp.recordTrip("error_rate")
	exp.recordTrip("error_rate")

	if got := counterValue(t, m.ThresholdTripped, map[string]string{
		"cr_namespace": "ns", "cr_name": "cr", "threshold": "error_rate",
	}); got != 2 {
		t.Errorf("error_rate counter via recordTrip = %v, want 2", got)
	}
}

// TestPodEnricher_StatsNilReceiver covers the nil short-circuit of Stats
// (the branch the populated-path test does not reach) and confirms a
// populated enricher reports the activity it observed.
func TestPodEnricher_StatsNilReceiver(t *testing.T) {
	var nilE *PodEnricher
	if got := nilE.Stats(); got != (EnricherStats{}) {
		t.Errorf("nil enricher Stats = %+v, want zero value", got)
	}

	e := NewPodEnricher()
	pod := newPodWithOwner("ns", "p", "u1", "n", "Deployment", "web", "web-7d8c9c")
	e.Snapshot([]PodCgroupEntry{{CgroupID: 1, Pod: pod, ContainerName: "app"}})

	if _, ok := e.Lookup(1); !ok {
		t.Fatal("expected hit on snapshotted cgroup")
	}
	if _, ok := e.Lookup(999); ok {
		t.Fatal("expected miss on unknown cgroup")
	}

	s := e.Stats()
	if s.Hits != 1 {
		t.Errorf("Stats.Hits = %d, want 1", s.Hits)
	}
	if s.Misses != 1 {
		t.Errorf("Stats.Misses = %d, want 1", s.Misses)
	}
	if s.Snapshots != 1 {
		t.Errorf("Stats.Snapshots = %d, want 1", s.Snapshots)
	}
	if s.OwnerResolved != 1 {
		t.Errorf("Stats.OwnerResolved = %d, want 1", s.OwnerResolved)
	}
	if s.CacheSize != 1 {
		t.Errorf("Stats.CacheSize = %d, want 1", s.CacheSize)
	}
}

// TestFallbackLegacyTarget_NoMatch covers the loop path where no pod's
// cgroup path matches the requested ID, leaving the target set unchanged.
// On a test host there are no kubepods cgroup roots, so discoverKubepodsRoot
// returns "" and every cgroupPathForPod returns "" — the canonical no-match
// case. (The append branch needs a live cgroup whose inode equals the ID,
// which requires a real kubelet cgroup hierarchy, so it is not unit-testable.)
func TestFallbackLegacyTarget_NoMatch(t *testing.T) {
	pods := []*corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "p1",
				Namespace: "ns",
				UID:       "11111111-2222-3333-4444-555555555555",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "p2",
				Namespace: "ns",
				UID:       "66666666-7777-8888-9999-000000000000",
			},
		},
	}

	out := tracer.TargetSet{}
	fallbackLegacyTarget(&out, pods, 4242)
	if len(out) != 0 {
		t.Errorf("no pod cgroup should match a synthetic ID, got %d targets: %+v", len(out), out)
	}

	seed := tracer.Target{PodName: "seed", Namespace: "ns"}
	out2 := tracer.TargetSet{seed}
	fallbackLegacyTarget(&out2, pods, 4242)
	if len(out2) != 1 || out2[0].PodName != "seed" {
		t.Errorf("no-match must preserve existing targets, got %+v", out2)
	}
}
