package agent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/operator"
	bundlepkg "github.com/podtrace/podtrace/pkg/exporter/bundle"
	"github.com/podtrace/podtrace/pkg/tracer"
)

type fakeExporter struct {
	mu      sync.Mutex
	name    string
	exports int
	closed  int
}

func (e *fakeExporter) Name() string { return e.name }
func (e *fakeExporter) Export(_ context.Context, batch []*events.Event) error {
	e.exports++
	return nil
}
func (e *fakeExporter) Close(_ context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed++
	return nil
}

// waitForCloses polls until the exporter's Close count reaches want.
// Displaced exporters are closed asynchronously after Router.Publish (so a
// hung collector cannot stall the reconcile loop), hence the wait.
func waitForCloses(t *testing.T, e *fakeExporter, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e.Closes() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("exporter %s Close count = %d, want %d", e.name, e.Closes(), want)
}

func (e *fakeExporter) Closes() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closed
}

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("corev1 AddToScheme: %v", err)
	}
	if err := podtracev1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("podtracev1alpha1 AddToScheme: %v", err)
	}
	return s
}

func makeBundleCM(systemNS string, uid types.UID, rv string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            operator.ExporterBundleName(uid),
			Namespace:       systemNS,
			ResourceVersion: rv,
			Labels: map[string]string{
				operator.LabelManagedBy: operator.ManagedByValue,
				operator.LabelComponent: operator.ComponentBundle,
			},
		},
		Data: map[string]string{"type": "otlp", "endpoint": "noop:4318"},
	}
}

func TestFiltersToSet_DedupesAcrossCategories(t *testing.T) {
	in := []podtracev1alpha1.EventFilter{
		podtracev1alpha1.FilterDNS,
		podtracev1alpha1.FilterFS,
		podtracev1alpha1.FilterFS, // dedup
	}
	got := filtersToSet(in)
	want := []events.EventType{
		events.EventDNS, events.EventDNSQuery,
		events.EventOpen, events.EventClose,
		events.EventRead, events.EventWrite, events.EventFsync,
		events.EventUnlink, events.EventRename,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d (%v)", len(got), len(want), got)
	}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("missing %v", w)
		}
	}
}

func TestFilterToEventTypes_AllCategories(t *testing.T) {
	cases := []struct {
		in     podtracev1alpha1.EventFilter
		nonNil bool
	}{
		{podtracev1alpha1.FilterDNS, true},
		{podtracev1alpha1.FilterNet, true},
		{podtracev1alpha1.FilterFS, true},
		{podtracev1alpha1.FilterCPU, true},
		{podtracev1alpha1.FilterProc, true},
		{podtracev1alpha1.FilterCrypto, true},
		{"unknown-filter", false},
	}
	for _, c := range cases {
		out := filterToEventTypes(c.in)
		if c.nonNil && len(out) == 0 {
			t.Errorf("%q: expected non-empty mapping", c.in)
		}
		if !c.nonNil && len(out) != 0 {
			t.Errorf("%q: expected empty mapping, got %v", c.in, out)
		}
	}
}

// TestFilterToEventTypes_NetIncludesHTTP guards against the socket-level
// HTTP/1.x events being dropped by the agent router.
func TestFilterToEventTypes_NetIncludesHTTP(t *testing.T) {
	got := filterToEventTypes(podtracev1alpha1.FilterNet)
	want := map[events.EventType]bool{
		events.EventHTTPReq:    false,
		events.EventHTTPResp:   false,
		events.EventGRPCMethod: false,
	}
	for _, et := range got {
		if _, ok := want[et]; ok {
			want[et] = true
		}
	}
	for et, found := range want {
		if !found {
			t.Errorf("FilterNet missing event type %v — HTTP endpoints would be dropped by the router", et)
		}
	}
}

func TestPodChangePredicates(t *testing.T) {
	p := podChangePredicates()

	if !p.Create(event.CreateEvent{Object: &corev1.Pod{}}) {
		t.Error("Create predicate should accept all events")
	}
	if !p.Delete(event.DeleteEvent{Object: &corev1.Pod{}}) {
		t.Error("Delete predicate should accept all events")
	}
	if p.Generic(event.GenericEvent{Object: &corev1.Pod{}}) {
		t.Error("Generic predicate should reject events")
	}

	old := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"a": "1"}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	same := old.DeepCopy()
	if p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: same}) {
		t.Error("identical Update should be filtered out")
	}

	relabeled := old.DeepCopy()
	relabeled.Labels["a"] = "2"
	if !p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: relabeled}) {
		t.Error("label change Update should pass")
	}

	rephased := old.DeepCopy()
	rephased.Status.Phase = corev1.PodPending
	if !p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: rephased}) {
		t.Error("state-change Update should pass")
	}

	if p.Update(event.UpdateEvent{ObjectOld: &corev1.ConfigMap{}, ObjectNew: &corev1.Pod{}}) {
		t.Error("non-Pod Update should be rejected")
	}
}

func TestReconcile_HappyPath(t *testing.T) {
	const node, sysNS, ns = "node-1", "podtrace-system", "default"
	uid := types.UID("uid-1")

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: uid},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Filters:     []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterDNS},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ignored"},
		},
	}
	podOnNode := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "p1", Namespace: ns,
			Labels: map[string]string{"app": "api"},
		},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	podOffNode := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "p2", Namespace: ns,
			Labels: map[string]string{"app": "api"},
		},
		Spec:   corev1.PodSpec{NodeName: "other"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(pt, podOnNode, podOffNode, makeBundleCM(sysNS, uid, "10")).
		Build()

	exp := &fakeExporter{name: "fx"}
	builds := 0
	r := &AgentReconciler{
		Client:          c,
		NodeName:        node,
		SystemNamespace: sysNS,
		Router:          NewRouter(nil),
		Metrics:         NewMetrics(),
		TargetsCh:       make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			builds++
			return exp, nil
		},
		CgroupResolver: func(pods []*corev1.Pod) (map[uint64]struct{}, error) {
			out := map[uint64]struct{}{}
			for range pods {
				out[42] = struct{}{}
			}
			return out, nil
		},
		exporterCache: map[CRKey]cachedExporter{},
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if builds != 1 {
		t.Errorf("ExporterBuilder calls = %d, want 1", builds)
	}
	rules := r.Router.RulesSnapshot()
	if len(rules) != 1 {
		t.Fatalf("router rules = %d, want 1 (only on-node pods should match)", len(rules))
	}
	if rules[0].MatchedPods != 1 {
		t.Errorf("MatchedPods = %d, want 1", rules[0].MatchedPods)
	}
	if _, ok := rules[0].CgroupIDs[42]; !ok {
		t.Error("CgroupIDs missing the resolver-supplied id")
	}
	if rules[0].BundleRevision != "10" {
		t.Errorf("BundleRevision = %q, want 10", rules[0].BundleRevision)
	}

	select {
	case <-r.TargetsCh:
	default:
		t.Error("TargetsCh did not receive a target set")
	}

	// Second reconcile with unchanged bundle RV must NOT rebuild the exporter.
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	}); err != nil {
		t.Fatalf("Reconcile (2nd): %v", err)
	}
	if builds != 1 {
		t.Errorf("ExporterBuilder calls after no-op reconcile = %d, want 1", builds)
	}
}

func TestReconcile_BundleRotationRebuildsExporter(t *testing.T) {
	const node, sysNS, ns = "node-1", "podtrace-system", "default"
	uid := types.UID("uid-1")

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: uid},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns, Labels: map[string]string{"app": "api"}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cm := makeBundleCM(sysNS, uid, "1")

	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(pt, pod, cm).Build()

	old := &fakeExporter{name: "old"}
	new1 := &fakeExporter{name: "new"}
	calls := 0
	r := &AgentReconciler{
		Client: c, NodeName: node, SystemNamespace: sysNS,
		Router: NewRouter(nil), TargetsCh: make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(p *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			calls++
			if p.ResourceVer == "1" {
				return old, nil
			}
			return new1, nil
		},
		CgroupResolver: func(_ []*corev1.Pod) (map[uint64]struct{}, error) {
			return map[uint64]struct{}{1: {}}, nil
		},
		exporterCache: map[CRKey]cachedExporter{},
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	}); err != nil {
		t.Fatal(err)
	}

	var current corev1.ConfigMap
	if err := c.Get(context.Background(), types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, &current); err != nil {
		t.Fatalf("get: %v", err)
	}
	current.Data["sample_percent"] = "10" // arbitrary mutation
	if err := c.Update(context.Background(), &current); err != nil {
		t.Fatalf("update: %v", err)
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	}); err != nil {
		t.Fatal(err)
	}

	if calls != 2 {
		t.Errorf("ExporterBuilder calls = %d, want 2 (rotation should rebuild)", calls)
	}
	waitForCloses(t, old, 1)
	if new1.Closes() != 0 {
		t.Errorf("new exporter Close count = %d, want 0", new1.Closes())
	}
}

func TestReconcile_PausedCRSkipped(t *testing.T) {
	const node, sysNS, ns = "node-1", "podtrace-system", "default"
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: "uid-paused"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
			Paused:      true,
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns, Labels: map[string]string{"app": "api"}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(pt, pod).Build()

	calls := 0
	r := &AgentReconciler{
		Client: c, NodeName: node, SystemNamespace: sysNS,
		Router: NewRouter(nil), TargetsCh: make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			calls++
			return &fakeExporter{}, nil
		},
		CgroupResolver: func(_ []*corev1.Pod) (map[uint64]struct{}, error) {
			t.Fatal("CgroupResolver must not be called for paused CRs")
			return nil, nil
		},
		exporterCache: map[CRKey]cachedExporter{},
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Errorf("ExporterBuilder unexpectedly called %d times", calls)
	}
	if got := len(r.Router.RulesSnapshot()); got != 0 {
		t.Errorf("router rules = %d, want 0", got)
	}
}

func TestReconcile_NoMatchedPodsReleasesExporter(t *testing.T) {
	const node, sysNS, ns = "node-1", "podtrace-system", "default"
	uid := types.UID("uid-empty")

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: uid},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "missing"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).
		WithObjects(pt, makeBundleCM(sysNS, uid, "1")).Build()

	exp := &fakeExporter{name: "stale"}
	r := &AgentReconciler{
		Client: c, NodeName: node, SystemNamespace: sysNS,
		Router: NewRouter(nil), TargetsCh: make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			return &fakeExporter{}, nil
		},
		CgroupResolver: func(_ []*corev1.Pod) (map[uint64]struct{}, error) {
			return map[uint64]struct{}{}, nil
		},
		exporterCache: map[CRKey]cachedExporter{
			{Namespace: ns, Name: "pt"}: {bundleRV: "0", exporter: exp},
		},
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	}); err != nil {
		t.Fatal(err)
	}
	waitForCloses(t, exp, 1)
	if _, ok := r.exporterCache[CRKey{Namespace: ns, Name: "pt"}]; ok {
		t.Error("exporter cache should be empty after release")
	}
}

func TestReconcile_BundleNotFoundIsNonFatal(t *testing.T) {
	const node, sysNS, ns = "node-1", "podtrace-system", "default"
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: "uid-no-bundle"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns, Labels: map[string]string{"app": "x"}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(pt, pod).Build()

	r := &AgentReconciler{
		Client: c, NodeName: node, SystemNamespace: sysNS,
		Router: NewRouter(nil), TargetsCh: make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			t.Fatal("ExporterBuilder must not be called when bundle is missing")
			return nil, nil
		},
		CgroupResolver: func(_ []*corev1.Pod) (map[uint64]struct{}, error) {
			return map[uint64]struct{}{1: {}}, nil
		},
		exporterCache: map[CRKey]cachedExporter{},
	}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	})
	if err != nil {
		t.Fatalf("expected nil error for missing bundle, got %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("expected zero result, got %+v", res)
	}
	if got := len(r.Router.RulesSnapshot()); got != 0 {
		t.Errorf("router rules = %d, want 0", got)
	}
}

func TestReconcile_ExporterBuilderErrorPublishesTombstone(t *testing.T) {
	const node, sysNS, ns = "n", "ns-sys", "default"
	uid := types.UID("uid-err")
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: uid},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns, Labels: map[string]string{"a": "b"}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).
		WithObjects(pt, pod, makeBundleCM(sysNS, uid, "1")).Build()

	r := &AgentReconciler{
		Client: c, NodeName: node, SystemNamespace: sysNS,
		Router: NewRouter(nil), TargetsCh: make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			return nil, errors.New("not yet implemented")
		},
		CgroupResolver: func(_ []*corev1.Pod) (map[uint64]struct{}, error) {
			return map[uint64]struct{}{1: {}}, nil
		},
		exporterCache: map[CRKey]cachedExporter{},
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	}); err != nil {
		t.Fatalf("Reconcile must not propagate exporter-build errors: %v", err)
	}

	rules := r.Router.RulesSnapshot()
	if len(rules) != 1 {
		t.Fatalf("want 1 tombstone rule, got %d", len(rules))
	}
	rule := rules[0]
	if rule.Err == nil {
		t.Fatal("tombstone rule must carry Err")
	}
	if rule.Exporter != nil {
		t.Error("tombstone rule must have nil Exporter")
	}
	if !strings.Contains(rule.Err.Error(), "build exporter") {
		t.Errorf("err = %q; expected 'build exporter:' prefix", rule.Err.Error())
	}
	if !strings.Contains(rule.Err.Error(), "not yet implemented") {
		t.Errorf("err = %q; expected wrapped builder error", rule.Err.Error())
	}
	if len(rule.CgroupIDs) != 1 {
		t.Errorf("CgroupIDs = %d, want 1 (kept for diagnostic visibility)", len(rule.CgroupIDs))
	}
	if rule.BundleRevision != "1" {
		t.Errorf("BundleRevision = %q, want 1", rule.BundleRevision)
	}

	if _, cached := r.exporterCache[CRKey{Namespace: ns, Name: "pt"}]; cached {
		t.Error("failed build must not leave a cached entry")
	}
}

func TestReconcile_CgroupResolverErrorPublishesTombstone(t *testing.T) {
	const node, sysNS, ns = "n", "ns-sys", "default"
	uid := types.UID("uid-cgerr")
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: uid},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Filters:     []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterDNS},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns, Labels: map[string]string{"a": "b"}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).
		WithObjects(pt, pod, makeBundleCM(sysNS, uid, "1")).Build()
	r := &AgentReconciler{
		Client: c, NodeName: node, SystemNamespace: sysNS,
		Router: NewRouter(nil), TargetsCh: make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			return &fakeExporter{}, nil
		},
		CgroupResolver: func(_ []*corev1.Pod) (map[uint64]struct{}, error) {
			return nil, errors.New("synthetic resolver error")
		},
		exporterCache: map[CRKey]cachedExporter{},
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	}); err != nil {
		t.Fatal(err)
	}
	rules := r.Router.RulesSnapshot()
	if len(rules) != 1 {
		t.Fatalf("want 1 tombstone rule, got %d", len(rules))
	}
	if rules[0].Err == nil || !strings.Contains(rules[0].Err.Error(), "resolve cgroup IDs") {
		t.Errorf("err = %v; expected 'resolve cgroup IDs:' prefix", rules[0].Err)
	}
	if rules[0].Exporter != nil {
		t.Error("tombstone rule must have nil Exporter")
	}
	if _, ok := rules[0].Filters[events.EventDNS]; !ok {
		t.Error("Filters not preserved on tombstone")
	}
}

func TestReconcile_BundleLoadErrorPublishesTombstone(t *testing.T) {
	const node, sysNS, ns = "n", "ns-sys", "default"
	uid := types.UID("uid-bundle-err")
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: uid},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns, Labels: map[string]string{"a": "b"}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	badCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      operator.ExporterBundleName(uid),
			Namespace: sysNS,
			Labels: map[string]string{
				operator.LabelManagedBy: operator.ManagedByValue,
				operator.LabelComponent: operator.ComponentBundle,
			},
		},
		Data: map[string]string{"type": "otlp", "sample_percent": "not-a-number"},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).
		WithObjects(pt, pod, badCM).Build()
	r := &AgentReconciler{
		Client: c, NodeName: node, SystemNamespace: sysNS,
		Router: NewRouter(nil), TargetsCh: make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			t.Fatal("ExporterBuilder must not be called when bundle parsing fails")
			return nil, nil
		},
		CgroupResolver: func(_ []*corev1.Pod) (map[uint64]struct{}, error) {
			return map[uint64]struct{}{1: {}}, nil
		},
		exporterCache: map[CRKey]cachedExporter{},
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	}); err != nil {
		t.Fatal(err)
	}
	rules := r.Router.RulesSnapshot()
	if len(rules) != 1 {
		t.Fatalf("want 1 tombstone rule, got %d", len(rules))
	}
	if rules[0].Err == nil || !strings.Contains(rules[0].Err.Error(), "load bundle") {
		t.Errorf("err = %v; expected 'load bundle:' prefix", rules[0].Err)
	}
	if rules[0].Exporter != nil {
		t.Error("tombstone rule must have nil Exporter")
	}
}

func TestReconcile_MatchPodsErrorPublishesTombstone(t *testing.T) {
	const node, sysNS, ns = "n", "ns-sys", "default"
	uid := types.UID("uid-match-err")
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: uid},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "k", Operator: "bogus-op", Values: []string{"v"}},
				},
			},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).
		WithObjects(pt, pod, makeBundleCM(sysNS, uid, "1")).Build()
	r := &AgentReconciler{
		Client: c, NodeName: node, SystemNamespace: sysNS,
		Router: NewRouter(nil), TargetsCh: make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			t.Fatal("ExporterBuilder must not be called when match fails")
			return nil, nil
		},
		CgroupResolver: func(_ []*corev1.Pod) (map[uint64]struct{}, error) {
			t.Fatal("CgroupResolver must not be called when match fails")
			return nil, nil
		},
		exporterCache: map[CRKey]cachedExporter{},
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	}); err != nil {
		t.Fatal(err)
	}
	rules := r.Router.RulesSnapshot()
	if len(rules) != 1 {
		t.Fatalf("want 1 tombstone rule, got %d", len(rules))
	}
	if rules[0].Err == nil || !strings.Contains(rules[0].Err.Error(), "match pods") {
		t.Errorf("err = %v; expected 'match pods:' prefix", rules[0].Err)
	}
}

func TestReconcile_ReapsExportersForDeletedCRs(t *testing.T) {
	const node, sysNS, ns = "n", "ns-sys", "default"
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()

	stale := &fakeExporter{name: "stale"}
	r := &AgentReconciler{
		Client: c, NodeName: node, SystemNamespace: sysNS,
		Router: NewRouter(nil), TargetsCh: make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			return &fakeExporter{}, nil
		},
		CgroupResolver: func(_ []*corev1.Pod) (map[uint64]struct{}, error) {
			return map[uint64]struct{}{}, nil
		},
		exporterCache: map[CRKey]cachedExporter{
			{Namespace: ns, Name: "deleted-cr"}: {bundleRV: "1", exporter: stale},
		},
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatal(err)
	}
	waitForCloses(t, stale, 1)
}

func TestReconcile_TargetsChannelKeepLatest(t *testing.T) {
	const node, sysNS, ns = "n", "s", "default"
	uid := types.UID("uid-ch")
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: uid},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns, Labels: map[string]string{"a": "b"}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).
		WithObjects(pt, pod, makeBundleCM(sysNS, uid, "1")).Build()

	r := &AgentReconciler{
		Client: c, NodeName: node, SystemNamespace: sysNS,
		Router:    NewRouter(nil),
		TargetsCh: make(chan tracer.TargetSet, 1), // 1-deep on purpose
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			return &fakeExporter{}, nil
		},
		CgroupResolver: func(_ []*corev1.Pod) (map[uint64]struct{}, error) {
			return map[uint64]struct{}{1: {}}, nil
		},
		exporterCache: map[CRKey]cachedExporter{},
	}
	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
			t.Fatalf("Reconcile #%d: %v", i, err)
		}
	}
}

func TestEnqueueAllPodTraces(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(
		&podtracev1alpha1.PodTrace{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns1"}},
		&podtracev1alpha1.PodTrace{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "ns2"}},
	).Build()
	r := &AgentReconciler{Client: c}
	got := r.enqueueAllPodTraces(context.Background(), &corev1.Pod{})
	if len(got) != 2 {
		t.Fatalf("got %d requests, want 2", len(got))
	}
}

func TestEnqueueOnBundleChange(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(
		&podtracev1alpha1.PodTrace{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns"}},
	).Build()
	r := &AgentReconciler{Client: c}

	if got := r.enqueueOnBundleChange(context.Background(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "ns"},
	}); len(got) != 0 {
		t.Errorf("unmanaged CM enqueued %d", len(got))
	}

	if got := r.enqueueOnBundleChange(context.Background(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "x", Namespace: "ns",
			Labels: map[string]string{
				operator.LabelManagedBy: operator.ManagedByValue,
				operator.LabelComponent: "other",
			},
		},
	}); len(got) != 0 {
		t.Errorf("wrong-component CM enqueued %d", len(got))
	}

	got := r.enqueueOnBundleChange(context.Background(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "x", Namespace: "ns",
			Labels: map[string]string{
				operator.LabelManagedBy: operator.ManagedByValue,
				operator.LabelComponent: operator.ComponentBundle,
			},
		},
	})
	if len(got) != 1 {
		t.Errorf("bundle CM enqueued %d, want 1", len(got))
	}

	gotSecret := r.enqueueOnBundleChange(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "x", Namespace: "ns",
			Labels: map[string]string{
				operator.LabelManagedBy: operator.ManagedByValue,
				operator.LabelComponent: operator.ComponentBundle,
			},
		},
	})
	if len(gotSecret) != 1 {
		t.Errorf("bundle Secret enqueued %d, want 1", len(gotSecret))
	}
}

func TestObtainAndReleaseExporter(t *testing.T) {
	calls := 0
	r := &AgentReconciler{
		exporterCache: map[CRKey]cachedExporter{},
		ExporterBuilder: func(p *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			calls++
			return &fakeExporter{name: p.ResourceVer}, nil
		},
	}
	key := CRKey{Namespace: "ns", Name: "pt"}

	exp1, err := r.obtainExporter(key, &BundlePayload{ResourceVer: "1"})
	if err != nil {
		t.Fatal(err)
	}
	exp2, err := r.obtainExporter(key, &BundlePayload{ResourceVer: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if exp1 != exp2 {
		t.Error("same-RV obtain returned a different exporter")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}

	exp3, err := r.obtainExporter(key, &BundlePayload{ResourceVer: "2"})
	if err != nil {
		t.Fatal(err)
	}
	if exp1 == exp3 {
		t.Error("RV bump must produce a new exporter")
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2", calls)
	}
	// Displaced exporters accumulate in pendingClose and are only closed by
	// the post-Publish drain — never inline, where in-flight Export calls
	// could still route into them.
	if exp1.(*fakeExporter).Closes() != 0 {
		t.Errorf("old exporter closed before drain, count = %d", exp1.(*fakeExporter).Closes())
	}
	r.closeDisplacedExporters()
	waitForCloses(t, exp1.(*fakeExporter), 1)

	r.releaseExporter(key)
	if _, ok := r.exporterCache[key]; ok {
		t.Error("releaseExporter did not remove the entry")
	}
	r.closeDisplacedExporters()
	waitForCloses(t, exp3.(*fakeExporter), 1)
	r.releaseExporter(key)
}

func TestObtainExporter_BuildErrorPropagates(t *testing.T) {
	r := &AgentReconciler{
		exporterCache: map[CRKey]cachedExporter{},
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			return nil, errors.New("nope")
		},
	}
	key := CRKey{Namespace: "ns", Name: "pt"}
	if _, err := r.obtainExporter(key, &BundlePayload{ResourceVer: "1"}); err == nil {
		t.Fatal("expected error")
	}
	if _, ok := r.exporterCache[key]; ok {
		t.Error("failed build must not populate the cache")
	}
}

func TestReapStaleExporters(t *testing.T) {
	a := &fakeExporter{name: "a"}
	b := &fakeExporter{name: "b"}
	r := &AgentReconciler{
		exporterCache: map[CRKey]cachedExporter{
			{Namespace: "ns", Name: "a"}: {bundleRV: "1", exporter: a},
			{Namespace: "ns", Name: "b"}: {bundleRV: "1", exporter: b},
		},
	}
	active := map[CRKey]struct{}{{Namespace: "ns", Name: "a"}: {}}
	r.reapStaleExporters(active)
	r.closeDisplacedExporters()
	if a.Closes() != 0 {
		t.Errorf("active exporter must not be closed, got %d", a.Closes())
	}
	waitForCloses(t, b, 1)
	if _, ok := r.exporterCache[CRKey{Namespace: "ns", Name: "b"}]; ok {
		t.Error("stale entry not removed")
	}
}

func TestCgroupIDFromPath_Errors(t *testing.T) {
	if _, err := cgroupIDFromPath("/non/existent/path/should/not/exist"); err == nil {
		t.Error("expected error for missing path")
	}
	// Use a real path so the syscall.Stat_t branch is exercised.
	id, err := cgroupIDFromPath(t.TempDir())
	if err != nil {
		t.Fatalf("expected success on tmpdir: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero inode for tmpdir")
	}
}

func TestCgroupPathForPod_NoMatch(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			UID: types.UID("definitely-not-a-real-pod-uid-0123456789abcdef"),
		},
		Status: corev1.PodStatus{QOSClass: corev1.PodQOSGuaranteed},
	}
	if got := cgroupPathForPod(pod, discoverKubepodsRoot()); got != "" {
		t.Errorf("expected empty path for synthetic UID, got %q", got)
	}
}

func TestResolveCgroupIDs_SkipsUnresolvable(t *testing.T) {
	pods := []*corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{UID: "synthetic-uid"},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{Name: "c"}},
			},
		},
	}
	out, err := resolveCgroupIDs(pods)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty result for synthetic pod, got %v", out)
	}
}

func TestBuildTargetSet_Deduplicates(t *testing.T) {
	rules := []CRRule{
		{CgroupIDs: map[uint64]struct{}{1: {}, 2: {}}},
		{CgroupIDs: map[uint64]struct{}{2: {}, 3: {}}},
	}
	out := buildTargetSet(rules, nil, nil)
	if len(out) != 0 {
		t.Errorf("expected empty output, got %+v", out)
	}
}

func TestPolicySnapshotFromBundle_FullRoundTrip(t *testing.T) {
	five := int32(5)
	twenty := int32(20)
	hundred := int32(100)
	b := &BundlePayload{
		Type:             "otlp",
		Endpoint:         "x:4318",
		Sample:           samplePtr(0.5),
		PolicyGeneration: 9,
		Filters: []bundlepkg.FilterCategory{
			bundlepkg.FilterDNS,
			bundlepkg.FilterFS,
		},
		Thresholds: &bundlepkg.Thresholds{
			ErrorRatePercent: &five,
			RTTSpikeMs:       &hundred,
			FSSlowMs:         &twenty,
		},
	}
	snap := policySnapshotFromBundle(b)
	if snap.EffectiveSamplePercent == nil || *snap.EffectiveSamplePercent != 50 {
		t.Errorf("EffectiveSamplePercent=%v want 50", snap.EffectiveSamplePercent)
	}
	if len(snap.Filters) != 2 || snap.Filters[0] != "dns" || snap.Filters[1] != "fs" {
		t.Errorf("Filters=%v want [dns fs]", snap.Filters)
	}
	if snap.Thresholds == nil ||
		*snap.Thresholds.ErrorRatePercent != 5 ||
		*snap.Thresholds.RTTSpikeMs != 100 ||
		*snap.Thresholds.FSSlowMs != 20 {
		t.Errorf("Thresholds=%+v incorrect", snap.Thresholds)
	}
	if snap.Generation != 9 {
		t.Errorf("Generation=%d want 9", snap.Generation)
	}
	if snap.Hash == "" {
		t.Error("Hash must be computed from bundle")
	}
}

func TestUnionCategoriesFromRules_NoFilterWidensToAll(t *testing.T) {
	rules := []CRRule{
		{Key: CRKey{Namespace: "ns", Name: "a"}, Categories: []string{"dns"}},
		{Key: CRKey{Namespace: "ns", Name: "b"}},
	}
	got := unionCategoriesFromRules(rules)
	want := []string{"cpu", "dns", "fs", "net", "proc"}
	if !equalStrings(got, want) {
		t.Errorf("union = %v, want %v", got, want)
	}
}

func TestUnionCategoriesFromRules_SortedDeduped(t *testing.T) {
	rules := []CRRule{
		{Key: CRKey{Namespace: "ns", Name: "a"}, Categories: []string{"net", "fs"}},
		{Key: CRKey{Namespace: "ns", Name: "b"}, Categories: []string{"fs", "dns"}},
		{Key: CRKey{Namespace: "ns", Name: "c"}, Categories: []string{"net"}},
	}
	got := unionCategoriesFromRules(rules)
	want := []string{"dns", "fs", "net"}
	if !equalStrings(got, want) {
		t.Errorf("union = %v, want %v", got, want)
	}
}

func TestUnionCategoriesFromRules_SkipsErroredRules(t *testing.T) {
	rules := []CRRule{
		{Key: CRKey{Namespace: "ns", Name: "ok"}, Categories: []string{"dns"}},
		{
			Key:        CRKey{Namespace: "ns", Name: "bad"},
			Categories: []string{"net", "fs"},
			Err:        errors.New("bundle load failed"),
		},
	}
	got := unionCategoriesFromRules(rules)
	want := []string{"dns"}
	if !equalStrings(got, want) {
		t.Errorf("errored rule must not contribute: got %v want %v", got, want)
	}
}

func TestUnionCategoriesFromRules_EmptyRulesEmptyUnion(t *testing.T) {
	got := unionCategoriesFromRules(nil)
	if got == nil {
		t.Fatal("union must return a non-nil slice so the gate can act on it")
	}
	if len(got) != 0 {
		t.Errorf("union = %v, want []", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPolicySnapshotFromBundle_NilSafe(t *testing.T) {
	snap := policySnapshotFromBundle(nil)
	if snap.EffectiveSamplePercent != nil ||
		snap.Filters != nil ||
		snap.Thresholds != nil ||
		snap.Generation != 0 ||
		snap.Hash != "" {
		t.Errorf("nil bundle should yield zero snapshot, got %+v", snap)
	}
}

func samplePtr(v float64) *float64 { return &v }
