package agent

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/podtrace/podtrace/internal/events"
)

func TestMetricsEngineObserver_OnTargetError(t *testing.T) {
	m := NewMetrics()
	obs := m.EngineObserver()

	obs.OnTargetError("attach", nil)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("OnTargetError panicked: %v", r)
		}
	}()
	obs.OnTargetError("detach", errors.New("cgroup attach refused"))
}

func TestMetricsEngineObserver_CgroupCounters(t *testing.T) {
	m := NewMetrics()
	obs := m.EngineObserver()

	obs.OnCgroupsAttached(0)
	obs.OnCgroupsAttached(3)
	obs.OnCgroupsDetached(-1)
	obs.OnCgroupsDetached(2)

	if got := scrapeMetric(t, m, `cgroups_attached_total`); got != 3 {
		t.Errorf("cgroups_attached_total = %d, want 3", got)
	}
	if got := scrapeMetric(t, m, `cgroups_detached_total`); got != 2 {
		t.Errorf("cgroups_detached_total = %d, want 2", got)
	}
}

func TestMetrics_NilReceiverGuards(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil *Metrics receiver panicked: %v", r)
		}
	}()
	var m *Metrics
	cr := CRKey{Namespace: "ns", Name: "cr"}

	if got := m.ObserveErrorRate(cr, 10, true); got {
		t.Error("nil receiver ObserveErrorRate should return false")
	}
	m.ObserveEffectiveSampleRate(cr, &BundlePayload{})
	m.dropPolicyMetrics(cr)
	m.RecordThresholdTripped(cr, "fs_slow")
	m.ObserveSpanBatched(cr, 1)
	m.ObserveExportDelivery(cr, 1, nil)
	m.ObserveExporterInit(cr, nil)
	m.RefreshFromEnricher(nil)
}

func TestMetrics_ObserveEffectiveSampleRate_NilBundleDefaultsToOne(t *testing.T) {
	m := NewMetrics()
	cr := CRKey{Namespace: "ns", Name: "cr"}
	lbls := prometheus.Labels{"cr_namespace": "ns", "cr_name": "cr"}

	m.ObserveEffectiveSampleRate(cr, nil)
	if got := gaugeValue(t, m.EffectiveSampleRate, lbls); got != 1.0 {
		t.Errorf("nil bundle → rate = %v, want 1.0", got)
	}

	rate := 0.25
	m.ObserveEffectiveSampleRate(cr, &BundlePayload{Sample: &rate, PolicyGeneration: 9})
	if got := gaugeValue(t, m.EffectiveSampleRate, lbls); got != 0.25 {
		t.Errorf("explicit sample → rate = %v, want 0.25", got)
	}
	if got := gaugeValue(t, m.PolicyGeneration, lbls); got != 9 {
		t.Errorf("policy_generation = %v, want 9", got)
	}
}

func TestMetrics_RefreshFromEnricher_EmitsAllDeltas(t *testing.T) {
	m := NewMetrics()
	e := NewPodEnricher()

	ctrl := true
	resolvedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: "web", UID: types.UID("uid-resolved"),
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "web-5f6c", Controller: &ctrl},
			},
		},
	}
	orphanPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: "loose", UID: types.UID("uid-orphan"),
		},
	}
	e.Snapshot([]PodCgroupEntry{
		{CgroupID: 100, Pod: resolvedPod},
		{CgroupID: 200, Pod: orphanPod},
	})

	if _, ok := e.Lookup(100); !ok {
		t.Fatal("expected hit on cgroup 100")
	}
	if _, ok := e.Lookup(200); !ok {
		t.Fatal("expected hit on cgroup 200")
	}
	if _, ok := e.Lookup(999); ok {
		t.Fatal("expected miss on cgroup 999")
	}

	m.RefreshFromEnricher(e)

	if got := scrapeMetric(t, m, `enrichment_lookups_total{result="hit"}`); got != 2 {
		t.Errorf("hit lookups = %d, want 2", got)
	}
	if got := scrapeMetric(t, m, `enrichment_lookups_total{result="miss"}`); got != 1 {
		t.Errorf("miss lookups = %d, want 1", got)
	}
	if got := scrapeMetric(t, m, `enrichment_owner_resolution_total{result="resolved"}`); got != 1 {
		t.Errorf("resolved = %d, want 1", got)
	}
	if got := scrapeMetric(t, m, `enrichment_owner_resolution_total{result="orphaned"}`); got != 1 {
		t.Errorf("orphaned = %d, want 1", got)
	}
	if got := scrapeMetric(t, m, `enrichment_snapshots_total`); got != 1 {
		t.Errorf("snapshots = %d, want 1", got)
	}
	if got := scrapeMetric(t, m, `enrichment_cache_size`); got != 2 {
		t.Errorf("cache_size = %d, want 2", got)
	}

	m.RefreshFromEnricher(e)
	if got := scrapeMetric(t, m, `enrichment_lookups_total{result="hit"}`); got != 2 {
		t.Errorf("idle refresh double-counted hits: %d", got)
	}
}

func TestMetrics_RefreshFromRouter_DroppedDeltaAndPolicySampleRate(t *testing.T) {
	m := NewMetrics()
	router := NewRouter(nil)
	fifty := int32(50)
	router.Publish([]CRRule{{
		Key:       CRKey{Namespace: "ns", Name: "pt"},
		CgroupIDs: map[uint64]struct{}{1: {}},
		Policy:    PolicySnapshot{EffectiveSamplePercent: &fifty, Generation: 4},
	}})
	router.Stats().incrDropped(CRKey{Namespace: "ns", Name: "pt"}, 4)

	m.RefreshFromRouter(router)

	if got := scrapeMetric(t, m, `events_dropped_total{cr_namespace="ns",cr_name="pt"}`); got != 4 {
		t.Errorf("events_dropped_total = %d, want 4", got)
	}
	lbls := prometheus.Labels{"cr_namespace": "ns", "cr_name": "pt"}
	if got := gaugeValue(t, m.EffectiveSampleRate, lbls); got != 0.5 {
		t.Errorf("effective_sample_rate = %v, want 0.5 (50%% policy)", got)
	}
	if got := gaugeValue(t, m.PolicyGeneration, lbls); got != 4 {
		t.Errorf("policy_generation = %v, want 4", got)
	}
}

func TestMetrics_RefreshFromRouter_DefaultSampleRateWhenPolicyUnset(t *testing.T) {
	m := NewMetrics()
	router := NewRouter(nil)
	router.Publish([]CRRule{
		mkRule("ns", "nopolicy", []uint64{1}, []events.EventType{events.EventDNS}, &recExp{}),
	})
	m.RefreshFromRouter(router)
	lbls := prometheus.Labels{"cr_namespace": "ns", "cr_name": "nopolicy"}
	if got := gaugeValue(t, m.EffectiveSampleRate, lbls); got != 1.0 {
		t.Errorf("effective_sample_rate = %v, want 1.0 (unset policy)", got)
	}
}
