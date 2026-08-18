package agent

import (
	"errors"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestObserveExportDelivery_RecordsAndShortCircuits(t *testing.T) {
	cr := CRKey{Namespace: "ns", Name: "cr"}

	var nilM *Metrics
	nilM.ObserveExportDelivery(cr, 5, errors.New("collector unreachable: no endpoint"))

	m := NewMetrics()

	m.ObserveExportDelivery(cr, 5, nil)
	m.ObserveExportDelivery(cr, 0, errors.New("missing endpoint for OTLP exporter"))
	m.ObserveExportDelivery(cr, -3, errors.New("missing endpoint for OTLP exporter"))

	if got := scrapeMetric(t, m, `export_delivery_dropped_total{cr_namespace="ns",cr_name="cr",reason="endpoint_missing"}`); got != 0 {
		t.Fatalf("guard branches recorded %d, want 0", got)
	}

	m.ObserveExportDelivery(cr, 4, errors.New("missing endpoint for OTLP exporter"))
	m.ObserveExportDelivery(cr, 3, errors.New("missing endpoint for OTLP exporter"))

	if got := counterValue(t, m.ExportDeliveryDropped, map[string]string{
		"cr_namespace": "ns", "cr_name": "cr", "reason": "endpoint_missing",
	}); got != 7 {
		t.Errorf("export_delivery_dropped_total = %v, want 7 (4+3)", got)
	}

	m.ObserveExportDelivery(cr, 2, errors.New("tls handshake failed"))
	if got := counterValue(t, m.ExportDeliveryDropped, map[string]string{
		"cr_namespace": "ns", "cr_name": "cr", "reason": "tls_invalid",
	}); got != 2 {
		t.Errorf("tls_invalid series = %v, want 2", got)
	}
}

func TestDropErrorRateDetector_RemovesAndNilSafe(t *testing.T) {
	var nilM *Metrics
	nilM.dropErrorRateDetector(CRKey{Namespace: "ns", Name: "gone"})

	m := NewMetrics()
	cr := CRKey{Namespace: "ns", Name: "cr"}

	breached := false
	for i := 0; i < errorRateMinSampleSize+5; i++ {
		if m.ObserveErrorRate(cr, 10, true) {
			breached = true
		}
	}
	if !breached {
		t.Fatal("expected a breach edge before drop")
	}

	m.detectorsMu.Lock()
	_, present := m.detectors[cr]
	m.detectorsMu.Unlock()
	if !present {
		t.Fatal("detector should be registered before drop")
	}

	m.dropErrorRateDetector(cr)
	m.detectorsMu.Lock()
	_, present = m.detectors[cr]
	m.detectorsMu.Unlock()
	if present {
		t.Error("dropErrorRateDetector left a stale detector in the map")
	}

	if m.ObserveErrorRate(cr, 10, true) {
		t.Error("freshly rebuilt detector breached below min sample size")
	}
}

func TestNewProbeServer_DefaultStallWindow(t *testing.T) {
	const addr = "127.0.0.1:0"

	s := NewProbeServer(addr, 0)
	if s == nil {
		t.Fatal("NewProbeServer returned nil")
		return
	}
	if s.Addr != addr {
		t.Errorf("Addr = %q, want %q", s.Addr, addr)
	}
	if s.stall != 90*time.Second {
		t.Errorf("non-positive stall should default to 90s, got %s", s.stall)
	}
	if s.IsReady() {
		t.Error("pristine ProbeServer should not be ready")
	}
	if s.lastHeartbeat.Load() == 0 {
		t.Error("constructor should record an initial heartbeat")
	}

	if neg := NewProbeServer(addr, -time.Second); neg.stall != 90*time.Second {
		t.Errorf("negative stall should default to 90s, got %s", neg.stall)
	}

	if pos := NewProbeServer(addr, 5*time.Second); pos.stall != 5*time.Second {
		t.Errorf("positive stall should be preserved, got %s", pos.stall)
	}
}

func TestClassifyRuleErr_Arms(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want podtracev1alpha1.NodeStatusReason
	}{
		{"NilErr", nil, ""},
		{"BundleLoad", errors.New("load bundle: boom"), podtracev1alpha1.NodeStatusReasonBundleLoadFailed},
		{"PodMatch", errors.New("match pods: bad selector"), podtracev1alpha1.NodeStatusReasonPodMatchFailed},
		{"CgroupResolution", errors.New("resolve cgroup IDs: missing"), podtracev1alpha1.NodeStatusReasonCgroupResolutionFailed},
		{"ExporterBuild", errors.New("build exporter: unsupported"), podtracev1alpha1.NodeStatusReasonExporterBuildFailed},
		{"PolicyContains", errors.New("failed to apply policy override"), podtracev1alpha1.NodeStatusReasonPolicyParseError},
		{"Unknown", errors.New("something exotic happened"), podtracev1alpha1.NodeStatusReasonUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRuleErr(tc.err); got != tc.want {
				t.Errorf("classifyRuleErr(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestResolveCgroupIDs_MatchedPodsZeroCgroupsErrors(t *testing.T) {
	pods := []*corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns", UID: types.UID("11111111-2222-3333-4444-555555555555")}},
		{ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: "ns", UID: types.UID("66666666-7777-8888-9999-000000000000")}},
	}

	got, err := resolveCgroupIDs(pods)
	if err == nil {
		t.Fatal("matched pods that resolve to zero cgroups must return an error, not a false-healthy success")
	}
	if got == nil {
		t.Fatal("resolveCgroupIDs returned a nil map, want non-nil")
	}
	if len(got) != 0 {
		t.Errorf("no kubepods root should yield 0 cgroup IDs, got %d", len(got))
	}

	empty, err := resolveCgroupIDs(nil)
	if err != nil || len(empty) != 0 {
		t.Errorf("nil pods: got (%v, %v), want (empty, nil)", empty, err)
	}
}

func TestResolveNodeName_EnvAndFallback(t *testing.T) {
	t.Setenv("NODE_NAME", "  worker-7  ")
	if got := ResolveNodeName(); got != "worker-7" {
		t.Errorf("with NODE_NAME set: got %q, want %q", got, "worker-7")
	}

	t.Setenv("NODE_NAME", "   ")
	host, hostErr := os.Hostname()
	got := ResolveNodeName()
	if hostErr == nil && host != "" {
		if got != host {
			t.Errorf("blank NODE_NAME should fall back to hostname %q, got %q", host, got)
		}
	} else if got != "" {
		t.Errorf("blank NODE_NAME and no hostname should yield empty, got %q", got)
	}
}
