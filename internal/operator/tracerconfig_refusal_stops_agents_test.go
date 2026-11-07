package operator

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func reconcileTracerConfig(t *testing.T, r *TracerConfigReconciler) error {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName}})
	return err
}

func agentDaemonSetPresent(t *testing.T, c client.Client, namespace string) bool {
	t.Helper()
	var ds appsv1.DaemonSet
	err := c.Get(context.Background(), types.NamespacedName{Name: AgentDaemonSetName(DefaultTracerConfigName), Namespace: namespace}, &ds)
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

func readyCondition(t *testing.T, c client.Client) *metav1.Condition {
	t.Helper()
	var tc podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: DefaultTracerConfigName}, &tc); err != nil {
		t.Fatal(err)
	}
	return meta.FindStatusCondition(tc.Status.Conditions, ConditionReady)
}

func ownedAgentDaemonSet(tc *podtracev1alpha1.TracerConfig, namespace, image string, controlled bool) *appsv1.DaemonSet {
	ds := &appsv1.DaemonSet{
		ObjectMeta: ManagedObjectMeta(AgentDaemonSetName(tc.Name), namespace, ComponentAgent, agentObjectLabels(tc.Name)),
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: agentContainerName, Image: image}},
		}}},
	}
	if controlled {
		ds.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: podtracev1alpha1.GroupVersion.String(), Kind: "TracerConfig",
			Name: tc.Name, UID: tc.UID, Controller: boolPtr(true),
		}}
	}
	return ds
}

func TestTracerConfigRefusal_NarrowedAllowlistStopsRunningFleet(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "ghcr.io/gma1k/podtrace")
	c, r := reconcileFleets(t, []client.Object{fleetConfig(DefaultTracerConfigName, podtracev1alpha1.TracerConfigSpec{})}, DefaultTracerConfigName)
	if !agentDaemonSetPresent(t, c, r.SystemNamespace) {
		t.Fatal("setup: the fleet must be deployed first")
	}

	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "registry.internal/podtrace")
	if err := reconcileTracerConfig(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if agentDaemonSetPresent(t, c, r.SystemNamespace) {
		t.Fatal("agents still running an image the allowlist no longer admits must be stopped")
	}
	ready := readyCondition(t, c)
	if ready == nil || ready.Reason != "ImageNotAllowed" || !strings.Contains(ready.Message, "deleted agent DaemonSet") {
		t.Errorf("Ready = %+v, want ImageNotAllowed naming the deleted DaemonSet", ready)
	}
}

func TestTracerConfigRefusal_DisallowedEditKeepsCompliantFleetRunning(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "ghcr.io/gma1k/podtrace")
	c, r := reconcileFleets(t, []client.Object{fleetConfig(DefaultTracerConfigName, podtracev1alpha1.TracerConfigSpec{})}, DefaultTracerConfigName)

	var tc podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: DefaultTracerConfigName}, &tc); err != nil {
		t.Fatal(err)
	}
	tc.Spec.Image = "evil.example/agent:1"
	if err := c.Update(context.Background(), &tc); err != nil {
		t.Fatal(err)
	}
	if err := reconcileTracerConfig(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !agentDaemonSetPresent(t, c, r.SystemNamespace) {
		t.Fatal("a refused edit must not tear down agents that still run an allowed image")
	}
	var ds appsv1.DaemonSet
	if err := c.Get(context.Background(), types.NamespacedName{Name: AgentDaemonSetName(DefaultTracerConfigName), Namespace: r.SystemNamespace}, &ds); err != nil {
		t.Fatal(err)
	}
	if image := ds.Spec.Template.Spec.Containers[0].Image; image != "ghcr.io/gma1k/podtrace:test" {
		t.Errorf("DaemonSet image = %q, want the previously allowed image kept", image)
	}
	if ready := readyCondition(t, c); ready == nil || ready.Reason != "ImageNotAllowed" {
		t.Errorf("Ready = %+v, want the refusal still reported", ready)
	}
	var refused podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: DefaultTracerConfigName}, &refused); err != nil {
		t.Fatal(err)
	}
	if cond := meta.FindStatusCondition(refused.Status.Conditions, ConditionReconciled); cond == nil || cond.Status != metav1.ConditionFalse {
		t.Errorf("Reconciled = %+v, want False while the config is refused", cond)
	}
}

func TestTracerConfigRefusal_StopsAgentsInRefusedNamespaceOnly(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "ghcr.io/gma1k/podtrace")
	tc := fleetConfig(DefaultTracerConfigName, podtracev1alpha1.TracerConfigSpec{SystemNamespace: "kube-system"})
	c, _ := reconcileFleets(t, []client.Object{
		tc,
		ownedAgentDaemonSet(tc, "kube-system", "ghcr.io/gma1k/podtrace:test", true),
		ownedAgentDaemonSet(tc, "fleet-old", "ghcr.io/gma1k/podtrace:test", true),
	}, DefaultTracerConfigName)

	if agentDaemonSetPresent(t, c, "kube-system") {
		t.Error("agents in a refused system namespace must be stopped")
	}
	if !agentDaemonSetPresent(t, c, "fleet-old") {
		t.Error("agents in the earlier, valid system namespace must keep running")
	}
	if ready := readyCondition(t, c); ready == nil || ready.Reason != "SystemNamespaceInvalid" {
		t.Errorf("Ready = %+v, want SystemNamespaceInvalid", ready)
	}
}

func TestTracerConfigRefusal_LeavesDaemonSetsItDoesNotControl(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "ghcr.io/gma1k/podtrace")
	tc := fleetConfig(DefaultTracerConfigName, podtracev1alpha1.TracerConfigSpec{Image: "evil.example/agent:1"})
	c, _ := reconcileFleets(t, []client.Object{tc, ownedAgentDaemonSet(tc, "team-c", "evil.example/agent:1", false)}, DefaultTracerConfigName)

	if !agentDaemonSetPresent(t, c, "team-c") {
		t.Error("a DaemonSet that merely copies the agent labels is not this TracerConfig's to delete")
	}
}

func TestTracerConfigRefusal_DaemonSetListErrorIsRetried(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "ghcr.io/gma1k/podtrace")
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(fleetConfig(DefaultTracerConfigName, podtracev1alpha1.TracerConfigSpec{Image: "evil.example/agent:1"})).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*appsv1.DaemonSetList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	if err := reconcileTracerConfig(t, r); err == nil {
		t.Fatal("a refusal that could not check the running agents must be retried")
	}
	if ready := readyCondition(t, c); ready == nil || !strings.Contains(ready.Message, "list agent DaemonSets") {
		t.Errorf("Ready = %+v, want the failed check reported", ready)
	}
}

func TestTracerConfigRefusal_DaemonSetDeleteErrorIsRetried(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "ghcr.io/gma1k/podtrace")
	tc := fleetConfig(DefaultTracerConfigName, podtracev1alpha1.TracerConfigSpec{Image: "evil.example/agent:1"})
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc, ownedAgentDaemonSet(tc, "podtrace-system", "evil.example/agent:1", true)).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if _, ok := obj.(*appsv1.DaemonSet); ok {
					return errInternal()
				}
				return cl.Delete(ctx, obj, opts...)
			},
		}).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	if err := reconcileTracerConfig(t, r); err == nil {
		t.Fatal("a DaemonSet that could not be stopped must be retried")
	}
}
