package operator

import (
	"context"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func childOfSession(name, uid string) *corev1.ConfigMap {
	labels := map[string]string{
		LabelManagedBy:   ManagedByValue,
		LabelSessionName: "s",
		LabelSessionNS:   "default",
	}
	if uid != "" {
		labels[LabelSessionUID] = uid
	}
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name:              name,
		Namespace:         sessMoreSysNS,
		Labels:            labels,
		CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
	}}
}

func TestReapOrphanSessionChildren_ReapsChildrenOfAnEarlierSessionWithTheSameName(t *testing.T) {
	live := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) { s.UID = "uid-new" })
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(
		live,
		childOfSession("stale", "uid-old"),
		childOfSession("current", "uid-new"),
		childOfSession("legacy", ""),
	).Build()

	deleted, err := reapOrphanSessionChildren(context.Background(), c, time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want only the earlier session's child", deleted)
	}
	for name, want := range map[string]bool{"stale": false, "current": true, "legacy": true} {
		var cm corev1.ConfigMap
		err := c.Get(context.Background(), types.NamespacedName{Namespace: sessMoreSysNS, Name: name}, &cm)
		if (err == nil) != want {
			t.Errorf("%s present = %v, want %v", name, err == nil, want)
		}
	}
}

func TestOwnedSessionJobs_IgnoresJobsOfAnEarlierSessionWithTheSameName(t *testing.T) {
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) { s.UID = "uid-new" })
	earlier := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) { s.UID = "uid-old" })
	r := revocationReconciler(t, interceptor.Funcs{}, runningSessionJob(earlier, "n1"), runningSessionJob(s, "n2"))

	jobs, err := r.ownedSessionJobs(context.Background(), s, []string{sessMoreSysNS})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Name != SessionJobName(s.UID, "n2") {
		t.Errorf("owned Jobs = %d, want only the session's own Job", len(jobs))
	}
}

func TestSessionReconcile_StampsSessionUIDOnEveryChild(t *testing.T) {
	s := secretReportSession()
	s.CreationTimestamp = pendingDeadlineCreated
	s.Spec.PodRefs = []podtracev1alpha1.PodRef{{Namespace: "tenant-b", Name: "p2"}}
	ec := sessMoreFanOutObjects()[1].(*podtracev1alpha1.ExporterConfig)
	ec.Spec.OTLP.Headers = []podtracev1alpha1.OTLPHeader{{Name: "Authorization", ValueFrom: &podtracev1alpha1.SecretKeySelector{Name: "token", Key: "t"}}}
	objects := append(sessMoreFanOutObjects()[:1], ec, sessMoreFanOutObjects()[2], s, tenantNamespace("default"),
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "default"}, Data: map[string][]byte{"t": []byte("x")}},
		runningPod("p2", "tenant-b", "n1", nil),
	)
	r := frozenTargetsReconciler(t, objects...)
	r.nowFn = func() time.Time { return pendingDeadlineCreated.Add(time.Minute) }

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	selector := client.MatchingLabels{LabelSessionName: s.Name, LabelSessionNS: s.Namespace}
	lists := map[string]client.ObjectList{
		"Job":            &batchv1.JobList{},
		"ConfigMap":      &corev1.ConfigMapList{},
		"Secret":         &corev1.SecretList{},
		"ServiceAccount": &corev1.ServiceAccountList{},
		"Role":           &rbacv1.RoleList{},
		"RoleBinding":    &rbacv1.RoleBindingList{},
	}
	seen := map[string]int{}
	for kind, list := range lists {
		if err := r.List(context.Background(), list, selector); err != nil {
			t.Fatal(err)
		}
		for _, item := range metaItems(list) {
			if item.GetLabels()[labelReportKind] == reportKindValue {
				continue
			}
			seen[kind]++
			if got := item.GetLabels()[LabelSessionUID]; got != string(s.UID) {
				t.Errorf("%s %s/%s carries session-uid %q, want %q", kind, item.GetNamespace(), item.GetName(), got, s.UID)
			}
		}
	}
	for kind := range lists {
		if seen[kind] == 0 {
			t.Errorf("the reconcile created no %s to check", kind)
		}
	}
}

func metaItems(list client.ObjectList) []metav1.Object {
	var out []metav1.Object
	switch l := list.(type) {
	case *batchv1.JobList:
		for i := range l.Items {
			out = append(out, &l.Items[i])
		}
	case *corev1.ConfigMapList:
		for i := range l.Items {
			out = append(out, &l.Items[i])
		}
	case *corev1.SecretList:
		for i := range l.Items {
			out = append(out, &l.Items[i])
		}
	case *corev1.ServiceAccountList:
		for i := range l.Items {
			out = append(out, &l.Items[i])
		}
	case *rbacv1.RoleList:
		for i := range l.Items {
			out = append(out, &l.Items[i])
		}
	case *rbacv1.RoleBindingList:
		for i := range l.Items {
			out = append(out, &l.Items[i])
		}
	}
	return out
}
