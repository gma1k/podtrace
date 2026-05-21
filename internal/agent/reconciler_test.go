package agent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

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

// fakeExporter is a tracer.Exporter that records every Export call and
// surfaces a Close counter so we can assert the reconciler's
// release/reap paths properly free downstream resources.
type fakeExporter struct {
	mu      sync.Mutex
	name    string
	exports int
	closed  int
}

func (e *fakeExporter) Name() string                                          { return e.name }
func (e *fakeExporter) Export(_ context.Context, batch []*events.Event) error { e.exports++; return nil }
func (e *fakeExporter) Close(_ context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed++
	return nil
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

// makeBundleCM produces a managed ConfigMap whose name matches the
// PodTrace UID so LoadBundle finds it.
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
		events.EventDNS, events.EventOpen, events.EventClose,
		events.EventRead, events.EventWrite, events.EventFsync,
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

	// UpdateFunc: same labels + same state → false; different labels → true; different state → true.
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

	// Non-Pod ObjectOld/New → false.
	if p.Update(event.UpdateEvent{ObjectOld: &corev1.ConfigMap{}, ObjectNew: &corev1.Pod{}}) {
		t.Error("non-Pod Update should be rejected")
	}
}

// TestReconcile_HappyPath runs the reconcile loop end-to-end against a
// fake controller-runtime client. It seeds two pods on the local node,
// one PodTrace selecting them by label, and a bundle ConfigMap. The
// injected ExporterBuilder returns a fakeExporter and the injected
// CgroupResolver maps each pod to a synthetic ID.
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

	// TargetsCh should have received a (possibly empty) set.
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

// TestReconcile_BundleRotationRebuildsExporter changes the ConfigMap
// ResourceVersion between reconciles and asserts the cached exporter
// is closed and a fresh one is built.
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

	// Bump RV via Update (fake client auto-increments ResourceVersion).
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
	if old.Closes() != 1 {
		t.Errorf("old exporter Close count = %d, want 1", old.Closes())
	}
	if new1.Closes() != 0 {
		t.Errorf("new exporter Close count = %d, want 0", new1.Closes())
	}
}

// TestReconcile_PausedCRSkipped covers the early-continue branch that
// drops paused CRs from the active rule set without consulting the
// bundle.
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

// TestReconcile_NoMatchedPodsReleasesExporter exercises the
// match-empty branch: the cached exporter for that CR must be closed
// and removed.
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
	if exp.Closes() != 1 {
		t.Errorf("stale exporter Close count = %d, want 1", exp.Closes())
	}
	if _, ok := r.exporterCache[CRKey{Namespace: ns, Name: "pt"}]; ok {
		t.Error("exporter cache should be empty after release")
	}
}

// TestReconcile_BundleNotFoundIsNonFatal verifies that a missing
// bundle ConfigMap (e.g. the operator hasn't synced it yet) returns
// without error and without publishing a rule for the affected CR.
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
	// No bundle ConfigMap → LoadBundle returns NotFound which the
	// reconciler must treat as transient.

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
	if res.Requeue || res.RequeueAfter != 0 {
		t.Errorf("expected zero result, got %+v", res)
	}
	if got := len(r.Router.RulesSnapshot()); got != 0 {
		t.Errorf("router rules = %d, want 0", got)
	}
}

// TestReconcile_ExporterBuilderErrorIsNonFatal: builder failure logs
// and continues; no rule is published for that CR.
// TestReconcile_ExporterBuilderErrorPublishesTombstone covers the
// agent's failure-visibility contract for the most common case: a
// bundle the agent does not know how to build (e.g. unsupported
// exporter type). The reconcile must not crash, must publish a
// tombstone rule (so the status writer can surface the cause on
// NodeStatus.Message), and must not cache the failed exporter.
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

// TestReconcile_CgroupResolverErrorPublishesTombstone: resolver failure
// produces a tombstone rule that carries the wrapped error and a nil
// exporter. CgroupIDs is empty because resolution failed before we
// could obtain them.
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

// TestReconcile_BundleLoadErrorPublishesTombstone covers the non-
// NotFound bundle load failure path: a real apiserver / network error
// must tombstone the rule, but NotFound (operator hasn't synced yet)
// must stay a silent skip — see TestReconcile_BundleNotFoundIsNonFatal.
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

// TestReconcile_MatchPodsErrorPublishesTombstone covers the defensive
// tombstone for selector evaluation. The webhook normally catches bad
// label selectors at admission; this test verifies the agent's belt-
// and-braces behaviour when an invalid selector somehow reaches it.
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

// TestReconcile_ReapsExportersForDeletedCRs seeds a stale cached
// exporter with a key that no longer corresponds to any CR; the
// reaper must close and drop it.
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
	if stale.Closes() != 1 {
		t.Errorf("stale exporter Close count = %d, want 1", stale.Closes())
	}
}

// TestReconcile_TargetsChannelKeepLatest stresses the keep-latest
// fallback by calling Reconcile against a 1-buffer channel that no
// consumer is draining. Two reconciles must succeed.
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

// TestEnqueueAllPodTraces returns one request per existing PodTrace,
// regardless of the triggering object.
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

// TestEnqueueOnBundleChange filters out non-bundle ConfigMaps.
func TestEnqueueOnBundleChange(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(
		&podtracev1alpha1.PodTrace{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns"}},
	).Build()
	r := &AgentReconciler{Client: c}

	// Unmanaged ConfigMap → 0 requests.
	if got := r.enqueueOnBundleChange(context.Background(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "ns"},
	}); len(got) != 0 {
		t.Errorf("unmanaged CM enqueued %d", len(got))
	}

	// Managed but wrong component → 0 requests.
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

	// Bundle CM → enqueues all PodTraces.
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
}

// TestObtainAndReleaseExporter exercises cache miss → hit → bundle-RV change.
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

	// Miss.
	exp1, err := r.obtainExporter(key, &BundlePayload{ResourceVer: "1"})
	if err != nil {
		t.Fatal(err)
	}
	// Hit (same RV).
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

	// Rotation.
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
	// The old exporter must have been closed.
	if exp1.(*fakeExporter).Closes() != 1 {
		t.Errorf("old exporter Close count = %d, want 1", exp1.(*fakeExporter).Closes())
	}

	// Release.
	r.releaseExporter(key)
	if _, ok := r.exporterCache[key]; ok {
		t.Error("releaseExporter did not remove the entry")
	}
	if exp3.(*fakeExporter).Closes() != 1 {
		t.Errorf("released exporter Close count = %d, want 1", exp3.(*fakeExporter).Closes())
	}
	// Releasing an absent key is a no-op.
	r.releaseExporter(key)
}

// TestObtainExporter_BuildErrorPropagates verifies builder errors are
// surfaced and nothing is cached on failure.
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

// TestReapStaleExporters exercises both the no-op-when-active path and
// the close-on-stale path.
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
	if a.Closes() != 0 {
		t.Errorf("active exporter must not be closed, got %d", a.Closes())
	}
	if b.Closes() != 1 {
		t.Errorf("stale exporter close count = %d, want 1", b.Closes())
	}
	if _, ok := r.exporterCache[CRKey{Namespace: "ns", Name: "b"}]; ok {
		t.Error("stale entry not removed")
	}
}

// TestCgroupIDFromPath_Errors covers the bad-path branch (Stat failure)
// and a happy path resolved against the test's own working directory.
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

// TestCgroupPathForPod_NoMatch covers the all-candidates-miss branch
// by passing a synthetic UID that cannot exist on the host.
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

// TestResolveCgroupIDs_SkipsUnresolvable confirms that pods whose
// cgroup paths cannot be resolved are silently dropped (the next
// reconcile picks them up).
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

// TestBuildTargetSet_Deduplicates verifies the seen-cgroup-id guard
// keeps the same target out of the output twice.
func TestBuildTargetSet_Deduplicates(t *testing.T) {
	rules := []CRRule{
		{CgroupIDs: map[uint64]struct{}{1: {}, 2: {}}},
		{CgroupIDs: map[uint64]struct{}{2: {}, 3: {}}},
	}
	// Empty pod list: every cgroup ID is "unmatched", so the result is empty
	// — but the function must not panic and dedup must not crash on overlap.
	out := buildTargetSet(rules, nil, nil)
	if len(out) != 0 {
		t.Errorf("expected empty output, got %+v", out)
	}
}

// TestPolicySnapshotFromBundle_FullRoundTrip pins the operator→bundle
// →agent path: a bundle populated by the operator with effective
// sample, filters, thresholds, and generation surfaces in a
// PolicySnapshot the router carries on every CRRule.
func TestPolicySnapshotFromBundle_FullRoundTrip(t *testing.T) {
	five := int32(5)
	twenty := int32(20)
	hundred := int32(100)
	b := &BundlePayload{
		Type:             "otlp",
		Endpoint:         "x:4318",
		Sample:           0.5,
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

// TestPolicySnapshotFromBundle_NilSafe documents the agent contract:
// a nil bundle yields a zero-value snapshot, never panics.
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
