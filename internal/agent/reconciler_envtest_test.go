//go:build envtest
// +build envtest

package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/operator"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// recordingExporter collects every event delivered to it, keyed by a
// CR-scoped name. Test-local.
type recordingExporter struct {
	mu     sync.Mutex
	name   string
	events []*events.Event
}

func (e *recordingExporter) Name() string { return e.name }
func (e *recordingExporter) Export(_ context.Context, batch []*events.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, batch...)
	return nil
}
func (e *recordingExporter) Close(_ context.Context) error { return nil }
func (e *recordingExporter) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.events)
}

// TestAgentEnvtest_TwoOverlappingCRs_ProduceScopedStreams is the
// multi-CR merge acceptance test. It asserts that applying two
// PodTrace CRs with overlapping selectors on the same node produces:
func TestAgentEnvtest_TwoOverlappingCRs_ProduceScopedStreams(t *testing.T) {
	scheme, c := setupSharedEnvtest(t)
	_ = scheme
	systemNS := ensureSystemNamespace(t, c)
	ns := freshNamespace(t, c)
	const node = "test-node"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	createRunningPod(t, c, ns, "api-a", node, map[string]string{"app": "api"})
	createRunningPod(t, c, ns, "api-b", node, map[string]string{"app": "api"})

	cgroupIDByPod := map[string]uint64{
		"api-a": 1001,
		"api-b": 1002,
	}

	ptA := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "cr-a", Namespace: ns, UID: "uid-a"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Filters:     []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterDNS},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ignored"},
		},
	}
	ptB := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "cr-b", Namespace: ns, UID: "uid-b"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Filters:     []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterNet},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ignored"},
		},
	}
	if err := c.Create(ctx, ptA); err != nil {
		t.Fatalf("create ptA: %v", err)
	}
	if err := c.Create(ctx, ptB); err != nil {
		t.Fatalf("create ptB: %v", err)
	}

	for _, pt := range []*podtracev1alpha1.PodTrace{ptA, ptB} {
		bundle := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      operator.ExporterBundleName(pt.UID),
				Namespace: systemNS,
				Labels: map[string]string{
					operator.LabelManagedBy: operator.ManagedByValue,
					operator.LabelComponent: operator.ComponentBundle,
				},
			},
			Data: map[string]string{"type": "otlp", "endpoint": "noop:4318"},
		}
		if err := c.Create(ctx, bundle); err != nil {
			t.Fatalf("create bundle for %s: %v", pt.Name, err)
		}
	}

	recorders := map[CRKey]*recordingExporter{}
	buildExporter := func(_ *BundlePayload, key CRKey) (tracer.Exporter, error) {
		rec := &recordingExporter{name: key.String()}
		recorders[key] = rec
		return rec, nil
	}
	resolveCg := func(pods []*corev1.Pod) (map[uint64]struct{}, error) {
		out := map[uint64]struct{}{}
		for _, p := range pods {
			if id, ok := cgroupIDByPod[p.Name]; ok {
				out[id] = struct{}{}
			}
		}
		return out, nil
	}

	router := NewRouter(nil)
	targetsCh := make(chan tracer.TargetSet, 8)

	r := &AgentReconciler{
		Client:          c,
		NodeName:        node,
		SystemNamespace: systemNS,
		Router:          router,
		TargetsCh:       targetsCh,
		ExporterBuilder: buildExporter,
		CgroupResolver:  resolveCg,
	}
	r.exporterCache = map[CRKey]cachedExporter{}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: ptA.Name, Namespace: ns}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// --- assertion 1: Router holds both CRs with distinct filter sets ---
	rules := router.RulesSnapshot()
	if len(rules) != 2 {
		t.Fatalf("router rules = %d, want 2", len(rules))
	}
	byKey := map[CRKey]CRRule{}
	for _, r := range rules {
		byKey[r.Key] = r
	}
	ruleA, okA := byKey[CRKey{Namespace: ns, Name: "cr-a"}]
	ruleB, okB := byKey[CRKey{Namespace: ns, Name: "cr-b"}]
	if !okA || !okB {
		t.Fatalf("missing CR rules: %+v", byKey)
	}
	if _, ok := ruleA.Filters[events.EventDNS]; !ok {
		t.Error("CR-A filter missing EventDNS")
	}
	if _, ok := ruleA.Filters[events.EventConnect]; ok {
		t.Error("CR-A should not have EventConnect")
	}
	if _, ok := ruleB.Filters[events.EventConnect]; !ok {
		t.Error("CR-B filter missing EventConnect")
	}

	for _, id := range []uint64{1001, 1002} {
		if _, ok := ruleA.CgroupIDs[id]; !ok {
			t.Errorf("CR-A missing cgroup %d", id)
		}
		if _, ok := ruleB.CgroupIDs[id]; !ok {
			t.Errorf("CR-B missing cgroup %d", id)
		}
	}

	batch := []*events.Event{
		{CgroupID: 1001, Type: events.EventDNS},      // A only (B does not filter DNS)
		{CgroupID: 1001, Type: events.EventConnect},  // B only (A does not filter Connect)
		{CgroupID: 1002, Type: events.EventDNS},      // A only
		{CgroupID: 1002, Type: events.EventTCPSend},  // B only
		{CgroupID: 9999, Type: events.EventDNS},      // neither (cgroup unclaimed)
	}
	if err := router.Export(ctx, batch); err != nil {
		t.Fatalf("router.Export: %v", err)
	}

	recA := recorders[CRKey{Namespace: ns, Name: "cr-a"}]
	recB := recorders[CRKey{Namespace: ns, Name: "cr-b"}]
	if recA == nil || recB == nil {
		t.Fatalf("recorders missing: a=%v b=%v", recA != nil, recB != nil)
	}
	if recA.count() != 2 {
		t.Errorf("CR-A events=%d want 2", recA.count())
	}
	if recB.count() != 2 {
		t.Errorf("CR-B events=%d want 2", recB.count())
	}

	writer := &StatusWriter{
		Client:   c,
		NodeName: node,
		Router:   router,
		Ready:    func() bool { return true },
	}
	if err := writer.emitOnce(ctx); err != nil {
		t.Fatalf("status emit: %v", err)
	}
	for _, key := range []CRKey{
		{Namespace: ns, Name: "cr-a"},
		{Namespace: ns, Name: "cr-b"},
	} {
		var pt podtracev1alpha1.PodTrace
		if err := c.Get(ctx, types.NamespacedName{Namespace: key.Namespace, Name: key.Name}, &pt); err != nil {
			t.Fatalf("get %s: %v", key, err)
		}
		if len(pt.Status.NodeStatus) != 1 {
			t.Errorf("%s nodeStatus rows=%d want 1", key, len(pt.Status.NodeStatus))
			continue
		}
		row := pt.Status.NodeStatus[0]
		if row.Node != node {
			t.Errorf("%s node=%q want %q", key, row.Node, node)
		}
		if row.EventsTotal != 2 {
			t.Errorf("%s EventsTotal=%d want 2", key, row.EventsTotal)
		}
		if !row.Ready {
			t.Errorf("%s Ready=false", key)
		}
	}
}

func TestAgentEnvtest_EngineNoopBackendDispatch(t *testing.T) {
	scheme, c := setupSharedEnvtest(t)
	_ = scheme
	systemNS := ensureSystemNamespace(t, c)
	ns := freshNamespace(t, c)
	const node = "engine-test-node"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	createRunningPod(t, c, ns, "api-p", node, map[string]string{"app": "svc"})
	const cgID = uint64(42)

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: "uid-engine"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "svc"}},
			Filters:     []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterDNS},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	if err := c.Create(ctx, pt); err != nil {
		t.Fatalf("create pt: %v", err)
	}
	bundle := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      operator.ExporterBundleName(pt.UID),
			Namespace: systemNS,
			Labels: map[string]string{
				operator.LabelManagedBy: operator.ManagedByValue,
				operator.LabelComponent: operator.ComponentBundle,
			},
		},
		Data: map[string]string{"type": "otlp", "endpoint": "noop:4318"},
	}
	if err := c.Create(ctx, bundle); err != nil {
		t.Fatalf("create bundle: %v", err)
	}

	rec := &recordingExporter{name: "engine-rec"}
	router := NewRouter(nil)
	backend := newNoopBackend()
	engine, err := tracer.NewEngine(backend, []tracer.Exporter{router}, tracer.Config{EventBufferSize: 32, ExportBatchSize: 1})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	targetsCh := make(chan tracer.TargetSet, 4)
	engineDone := make(chan error, 1)
	go func() { engineDone <- engine.Run(ctx, targetsCh) }()

	r := &AgentReconciler{
		Client:          c,
		NodeName:        node,
		SystemNamespace: systemNS,
		Router:          router,
		TargetsCh:       targetsCh,
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) { return rec, nil },
		CgroupResolver: func(pods []*corev1.Pod) (map[uint64]struct{}, error) {
			out := map[uint64]struct{}{}
			for range pods {
				out[cgID] = struct{}{}
			}
			return out, nil
		},
		exporterCache: map[CRKey]cachedExporter{},
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: pt.Name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	for i := 0; i < 5; i++ {
		if !backend.Inject(&events.Event{CgroupID: cgID, Type: events.EventDNS}) {
			t.Fatalf("inject: backend not started")
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for rec.count() < 5 {
		if time.Now().After(deadline) {
			t.Fatalf("timeout: recorder got %d events, want 5", rec.count())
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case <-engineDone:
	case <-time.After(3 * time.Second):
		t.Error("engine did not shut down cleanly")
	}
}

func TestAgentEnvtest_TombstoneSurfacesOnNodeStatus(t *testing.T) {
	scheme, c := setupSharedEnvtest(t)
	_ = scheme
	systemNS := ensureSystemNamespace(t, c)
	ns := freshNamespace(t, c)
	const node = "tombstone-node"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	createRunningPod(t, c, ns, "svc", node, map[string]string{"app": "svc"})

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: "uid-tomb"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "svc"}},
			Filters:     []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterDNS},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ignored"},
		},
	}
	if err := c.Create(ctx, pt); err != nil {
		t.Fatalf("create pt: %v", err)
	}
	bundle := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      operator.ExporterBundleName(pt.UID),
			Namespace: systemNS,
			Labels: map[string]string{
				operator.LabelManagedBy: operator.ManagedByValue,
				operator.LabelComponent: operator.ComponentBundle,
			},
		},
		Data: map[string]string{"type": "jaeger", "endpoint": "http://jaeger:14250"},
	}
	if err := c.Create(ctx, bundle); err != nil {
		t.Fatalf("create bundle: %v", err)
	}

	router := NewRouter(nil)
	var buildShouldFail bool = true
	r := &AgentReconciler{
		Client:          c,
		NodeName:        node,
		SystemNamespace: systemNS,
		Router:          router,
		TargetsCh:       make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(p *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			if buildShouldFail {
				return nil, fmt.Errorf("exporter type %q not yet implemented in agent mode", p.Type)
			}
			return &recordingExporter{name: "fixed"}, nil
		},
		CgroupResolver: func(pods []*corev1.Pod) (map[uint64]struct{}, error) {
			out := map[uint64]struct{}{}
			for range pods {
				out[100] = struct{}{}
			}
			return out, nil
		},
		exporterCache: map[CRKey]cachedExporter{},
	}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: pt.Name}}); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	writer := &StatusWriter{Client: c, NodeName: node, Router: router, Ready: func() bool { return true }}
	if err := writer.emitOnce(ctx); err != nil {
		t.Fatalf("emitOnce 1: %v", err)
	}

	var got podtracev1alpha1.PodTrace
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: pt.Name}, &got); err != nil {
		t.Fatalf("get pt 1: %v", err)
	}
	if len(got.Status.NodeStatus) != 1 {
		t.Fatalf("rows after failure = %d, want 1", len(got.Status.NodeStatus))
	}
	row := got.Status.NodeStatus[0]
	if row.Ready {
		t.Error("Ready = true after build failure; want false")
	}
	if row.Message == "" {
		t.Fatal("Message is empty after build failure; tombstone should surface the cause")
	}
	if !strings.Contains(row.Message, "build exporter") {
		t.Errorf("Message = %q; expected 'build exporter:' prefix", row.Message)
	}
	if !strings.Contains(row.Message, "not yet implemented") {
		t.Errorf("Message = %q; expected wrapped builder error", row.Message)
	}

	buildShouldFail = false
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: pt.Name}}); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if err := writer.emitOnce(ctx); err != nil {
		t.Fatalf("emitOnce 2: %v", err)
	}

	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: pt.Name}, &got); err != nil {
		t.Fatalf("get pt 2: %v", err)
	}
	if len(got.Status.NodeStatus) != 1 {
		t.Fatalf("rows after recovery = %d, want 1", len(got.Status.NodeStatus))
	}
	row = got.Status.NodeStatus[0]
	if !row.Ready {
		t.Errorf("Ready = false after recovery; want true. Message=%q", row.Message)
	}
	if row.Message != "" {
		t.Errorf("Message = %q after recovery; want empty (stale messages confuse users)", row.Message)
	}
}
