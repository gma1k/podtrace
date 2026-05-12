//go:build envtest
// +build envtest

package operator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestPodTraceReconciler_NamespaceSelectorAllowlist(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const tracedKey = "podtrace.io/test-ns-selector-allowlist"
	matchNS := ensureLabeledNamespace(t, c, tracedKey, "yes")
	otherNS := ensureLabeledNamespace(t, c, tracedKey, "no")

	ensureExporterConfig(t, c, ns, "otlp")

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "ns-selector", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "otlp"},
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{tracedKey: "yes"},
			},
		},
	}
	if err := c.Create(ctx, pt); err != nil {
		t.Fatal(err)
	}

	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}
	bundleName := ExporterBundleName(pt.UID)
	doReconcile := func() error {
		_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns}})
		return err
	}

	wantAllowlist := func(want []string) func() error {
		sort.Strings(want)
		return func() error {
			var cm corev1.ConfigMap
			if err := c.Get(ctx, types.NamespacedName{Name: bundleName, Namespace: systemNS}, &cm); err != nil {
				return err
			}
			raw, ok := cm.Data["target_namespaces"]
			if !ok {
				return fmt.Errorf("bundle missing target_namespaces key")
			}
			got := strings.Split(raw, ",")
			sort.Strings(got)
			if !equalStringSlices(got, want) {
				return fmt.Errorf("bundle target_namespaces = %v, want %v", got, want)
			}
			var got2 podtracev1alpha1.PodTrace
			if err := c.Get(ctx, types.NamespacedName{Name: pt.Name, Namespace: ns}, &got2); err != nil {
				return err
			}
			gotStatus := append([]string(nil), got2.Status.TargetNamespaces...)
			sort.Strings(gotStatus)
			if !equalStringSlices(gotStatus, want) {
				return fmt.Errorf("status.targetNamespaces = %v, want %v", gotStatus, want)
			}
			return nil
		}
	}

	reconcileUntil(t, 10*time.Second, wantAllowlist([]string{matchNS}), doReconcile)

	// Re-label the previously-excluded namespace to bring it into scope.
	// The watch wiring is exercised by a manager run; here we drive
	// reconcile manually to verify the resolver picks up the new label.
	var nsObj corev1.Namespace
	if err := c.Get(ctx, types.NamespacedName{Name: otherNS}, &nsObj); err != nil {
		t.Fatal(err)
	}
	nsObj.Labels[tracedKey] = "yes"
	if err := c.Update(ctx, &nsObj); err != nil {
		t.Fatal(err)
	}

	reconcileUntil(t, 10*time.Second, wantAllowlist([]string{matchNS, otherNS}), doReconcile)
}

// TestPodTraceReconciler_NamespaceSelector_EmptyMatch covers the
// tri-state "selector set but matched zero namespaces" branch. The agent
// must see target_namespaces="" (key present, value empty) so it knows
// to match nothing, distinct from the unset case.
func TestPodTraceReconciler_NamespaceSelector_EmptyMatch(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ensureExporterConfig(t, c, ns, "otlp")

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "ns-empty", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "otlp"},
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"podtrace.io/never-set-by-anyone": "definitely-not",
				},
			},
		},
	}
	if err := c.Create(ctx, pt); err != nil {
		t.Fatal(err)
	}

	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}
	bundleName := ExporterBundleName(pt.UID)

	reconcileUntil(t, 10*time.Second,
		func() error {
			var cm corev1.ConfigMap
			if err := c.Get(ctx, types.NamespacedName{Name: bundleName, Namespace: systemNS}, &cm); err != nil {
				return err
			}
			raw, ok := cm.Data["target_namespaces"]
			if !ok {
				return fmt.Errorf("bundle missing target_namespaces key (empty-match must still write the key)")
			}
			if raw != "" {
				return fmt.Errorf("bundle target_namespaces = %q, want \"\"", raw)
			}
			return nil
		},
		func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns}})
			return err
		},
	)
}

// TestPodTraceReconciler_NamespaceToPodTraces_EnqueuesOnlySelectorUsers
// checks the watch handler — PodTraces without a NamespaceSelector are
// namespace-pinned and need no re-evaluation on Namespace events.
func TestPodTraceReconciler_NamespaceToPodTraces_EnqueuesOnlySelectorUsers(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ensureExporterConfig(t, c, ns, "otlp")
	withSel := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "with-sel", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:          &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			ExporterRef:       podtracev1alpha1.LocalObjectReference{Name: "otlp"},
			NamespaceSelector: &metav1.LabelSelector{},
		},
	}
	withoutSel := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "without-sel", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "y"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "otlp"},
		},
	}
	if err := c.Create(ctx, withSel); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, withoutSel); err != nil {
		t.Fatal(err)
	}

	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}
	reqs := r.namespaceToPodTraces(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "any-ns"}})

	var sawWithSel bool
	for _, rq := range reqs {
		if rq.Name == withoutSel.Name && rq.Namespace == ns {
			t.Errorf("namespaceToPodTraces requeued %q, which has no NamespaceSelector", rq.Name)
		}
		if rq.Name == withSel.Name && rq.Namespace == ns {
			sawWithSel = true
		}
	}
	if !sawWithSel {
		t.Errorf("namespaceToPodTraces did not enqueue %q/%q (got %+v)", ns, withSel.Name, reqs)
	}
}

func ensureLabeledNamespace(t *testing.T, c client.Client, key, value string) string {
	t.Helper()
	name := "ns-" + sanitiseDNS(t.Name()+"-"+value)
	if len(name) > 60 {
		name = name[:60]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nsObj := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{key: value}},
	}
	if err := c.Create(ctx, nsObj); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create labeled namespace %q: %v", name, err)
	}
	// If the namespace already existed from a prior run of the shared
	// envtest, the Create above no-ops — force the label onto it so the
	// selector sees what this test expects.
	var got corev1.Namespace
	if err := c.Get(ctx, types.NamespacedName{Name: name}, &got); err != nil {
		t.Fatalf("get labeled namespace %q: %v", name, err)
	}
	if got.Labels == nil {
		got.Labels = map[string]string{}
	}
	if got.Labels[key] != value {
		got.Labels[key] = value
		if err := c.Update(ctx, &got); err != nil {
			t.Fatalf("update labeled namespace %q: %v", name, err)
		}
	}
	return name
}

func equalStringSlices(a, b []string) bool {
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