package operator

import (
	"context"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func reaperSessionLabels(sessionName, sessionNS string) map[string]string {
	return map[string]string{
		LabelManagedBy:   ManagedByValue,
		LabelComponent:   ComponentSession,
		LabelSessionName: sessionName,
		LabelSessionNS:   sessionNS,
	}
}

func TestReapOrphanSessionChildren_DeletesOnlyOrphans(t *testing.T) {
	scheme := newOperatorScheme(t)
	now := time.Now()
	old := metav1.NewTime(now.Add(-time.Hour))
	young := metav1.NewTime(now)

	live := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "live", Namespace: "team-a"},
	}

	orphanJob := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name: "podtrace-gone-n1", Namespace: "podtrace-system",
		Labels: reaperSessionLabels("gone", "team-a"), CreationTimestamp: old,
	}}
	orphanCreds := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "creds-gone", Namespace: "podtrace-system",
		Labels: reaperSessionLabels("gone", "team-a"), CreationTimestamp: old,
	}}
	orphanSA := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Name: "sa-gone", Namespace: "podtrace-system",
		Labels: reaperSessionLabels("gone", "team-a"), CreationTimestamp: old,
	}}
	orphanCrossRB := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{
		Name: "podread-gone", Namespace: "team-b",
		Labels: reaperSessionLabels("gone", "team-a"), CreationTimestamp: old,
	}}

	liveJob := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name: "podtrace-live-n1", Namespace: "podtrace-system",
		Labels: reaperSessionLabels("live", "team-a"), CreationTimestamp: old,
	}}
	reportCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name: "report-gone", Namespace: "team-a",
		Labels: func() map[string]string {
			l := reaperSessionLabels("gone", "team-a")
			l[labelReportKind] = reportKindValue
			return l
		}(),
		CreationTimestamp: old,
	}}
	youngOrphan := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name: "podtrace-gone-n2", Namespace: "podtrace-system",
		Labels: reaperSessionLabels("gone", "team-a"), CreationTimestamp: young,
	}}
	agentRole := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{
		Name: "podtrace-agent", Namespace: "podtrace-system",
		Labels: map[string]string{LabelManagedBy: ManagedByValue}, CreationTimestamp: old,
	}}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(live, orphanJob, orphanCreds, orphanSA, orphanCrossRB,
			liveJob, reportCM, youngOrphan, agentRole).Build()

	ctx := context.Background()
	n, err := reapOrphanSessionChildren(ctx, c, now, 5*time.Minute)
	if err != nil {
		t.Fatalf("reap error = %v", err)
	}
	if n != 4 {
		t.Errorf("reaped %d, want 4 (orphan job + creds + SA + cross-ns RB)", n)
	}

	gone := func(name, ns string, obj client.Object) {
		if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, obj); !apierrors.IsNotFound(err) {
			t.Errorf("%T %s/%s should be reaped (err=%v)", obj, ns, name, err)
		}
	}
	present := func(name, ns string, obj client.Object) {
		if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, obj); err != nil {
			t.Errorf("%T %s/%s should survive: %v", obj, ns, name, err)
		}
	}

	gone(orphanJob.Name, orphanJob.Namespace, &batchv1.Job{})
	gone(orphanCreds.Name, orphanCreds.Namespace, &corev1.Secret{})
	gone(orphanSA.Name, orphanSA.Namespace, &corev1.ServiceAccount{})
	gone(orphanCrossRB.Name, orphanCrossRB.Namespace, &rbacv1.RoleBinding{})

	present(liveJob.Name, liveJob.Namespace, &batchv1.Job{})         // session alive
	present(reportCM.Name, reportCM.Namespace, &corev1.ConfigMap{})  // retained report object
	present(youngOrphan.Name, youngOrphan.Namespace, &batchv1.Job{}) // within grace
	present(agentRole.Name, agentRole.Namespace, &rbacv1.Role{})     // not a session child
}

func TestReapOrphanSessionChildren_NoGraceReapsYoung(t *testing.T) {
	scheme := newOperatorScheme(t)
	now := time.Now()
	youngOrphan := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name: "podtrace-gone-n2", Namespace: "podtrace-system",
		Labels: reaperSessionLabels("gone", "team-a"), CreationTimestamp: metav1.NewTime(now),
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(youngOrphan).Build()

	n, err := reapOrphanSessionChildren(context.Background(), c, now, 0)
	if err != nil {
		t.Fatalf("reap error = %v", err)
	}
	if n != 1 {
		t.Errorf("reaped %d, want 1 with grace=0", n)
	}
}
