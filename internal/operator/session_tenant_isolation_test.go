package operator

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func forgedStagingSecret(s *podtracev1alpha1.PodTraceSession, namespace, name string) *corev1.Secret {
	labels := reportStagingLabels(s)
	labels[LabelNodeName] = "n1"
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Data:       map[string][]byte{"report-n1.txt": []byte("forged"), "injected.txt": []byte("forged")},
	}
}

func TestPublishSessionSecretReport_IgnoresForgedStagingSecrets(t *testing.T) {
	s := secretReportSession()
	c := stagingClient(t, interceptor.Funcs{},
		stagedReport(s, "n1", "one"),
		forgedStagingSecret(s, "team-c", SessionReportStagingName(s.UID, "n1")),
		forgedStagingSecret(s, sessMoreSysNS, "not-a-staging-name"),
	)

	if err := publishSessionSecretReport(context.Background(), c, c, s, []string{sessMoreSysNS}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	var report corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: s.Namespace, Name: "report"}, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Data) != 1 || string(report.Data["report-n1.txt"]) != "one" {
		t.Errorf("report data = %v, want only the session's own staged report", report.Data)
	}
}

func TestPublishSessionSecretReport_OnlyForgedStagingIsNothingStaged(t *testing.T) {
	s := secretReportSession()
	c := stagingClient(t, interceptor.Funcs{}, forgedStagingSecret(s, "team-c", SessionReportStagingName(s.UID, "n1")))

	err := publishSessionSecretReport(context.Background(), c, c, s, []string{sessMoreSysNS})
	if !errors.Is(err, errNothingStaged) {
		t.Fatalf("a staging Secret outside the system namespaces must not count, got %v", err)
	}
}

func TestPublishSecretReport_SystemNamespaceLookupFailureIsRetried(t *testing.T) {
	s := secretReportSession()
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(stagedReport(s, "n1", "one")).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*podtracev1alpha1.TracerConfigList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}

	r.publishSecretReport(context.Background(), s)
	for _, cond := range s.Status.Conditions {
		if cond.Type == ConditionReportUploaded && cond.Reason == "PublishFailed" {
			return
		}
	}
	t.Errorf("conditions = %+v, want ReportUploaded PublishFailed so the publish is retried", s.Status.Conditions)
}

func capacityJob(namespace, name, node string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				LabelManagedBy:   ManagedByValue,
				LabelComponent:   ComponentSession,
				LabelSessionName: "other",
				LabelSessionNS:   "team-b",
				LabelNodeName:    node,
			},
		},
		Spec:   batchv1.JobSpec{Suspend: boolPtr(true)},
		Status: batchv1.JobStatus{Active: 1},
	}
}

func TestNodesAtCapacity_CountsOnlySystemNamespaceJobs(t *testing.T) {
	r := sessionResolver(t,
		testTracerConfig("default", "img:default", "", nil),
		testTracerConfig("pool-b", "img:pool-b", "fleet-b", nil),
		capacityJob("team-c", "pts-forged-n1", "n1"),
		capacityJob("team-c", "pts-forged-n2", "n2"),
		capacityJob("fleet-b", "pts-real-n2", "n2"),
	)

	over, err := r.nodesAtCapacity(context.Background(), []string{"n1", "n2"}, 1, "default", "s")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(over, []string{"n2"}) {
		t.Errorf("nodes at capacity = %v, want only n2, held by a Job in a fleet namespace", over)
	}
}

func TestNodesAtCapacity_TracerConfigListErrorIsReturned(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*podtracev1alpha1.TracerConfigList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}

	if _, err := r.nodesAtCapacity(context.Background(), []string{"n1"}, 1, "default", "s"); err == nil {
		t.Fatal("the capacity count must fail when the system namespaces cannot be resolved")
	}
}

func TestSessionSystemNamespaces_AlwaysIncludesOperatorNamespace(t *testing.T) {
	cases := map[string]struct {
		configs []client.Object
		want    []string
	}{
		"no TracerConfig":           {want: []string{"podtrace-system"}},
		"fleet in operator ns":      {configs: []client.Object{testTracerConfig("default", "img", "", nil)}, want: []string{"podtrace-system"}},
		"fleet elsewhere":           {configs: []client.Object{testTracerConfig("b", "img", "fleet-b", nil)}, want: []string{"fleet-b", "podtrace-system"}},
		"fleet sorted after the ns": {configs: []client.Object{testTracerConfig("a", "img", "aaa", nil), testTracerConfig("z", "img", "zzz", nil)}, want: []string{"aaa", "podtrace-system", "zzz"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(tc.configs...).Build()
			got, err := sessionSystemNamespaces(context.Background(), c, "podtrace-system")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("namespaces = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolveSessionTracerConfigs_RefusesDisallowedImage(t *testing.T) {
	cases := map[string]*podtracev1alpha1.PodTraceSession{
		"default config": sessionWithRef(""),
		"pinned config":  sessionWithRef("default"),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			r := sessionResolver(t, testTracerConfig("default", "evil.example/agent:1", "", nil))

			_, err := r.resolveSessionTracerConfigs(context.Background(), s, []string{"n1"})
			var refused *errNoTracerConfig
			if !errors.As(err, &refused) || !refused.refused {
				t.Fatalf("want a refused errNoTracerConfig, got %v", err)
			}
			if !strings.Contains(err.Error(), "not in the operator's allowed set") {
				t.Errorf("error %q must explain the image allowlist", err)
			}
		})
	}
}

func TestSessionReconcile_DisallowedImageFailsWithoutJob(t *testing.T) {
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) { s.CreationTimestamp = pendingDeadlineCreated })
	objects := sessMoreFanOutObjects()
	objects[2].(*podtracev1alpha1.TracerConfig).Spec.Image = "evil.example/agent:1"
	objects = append(objects, s)
	r := revocationReconciler(t, interceptor.Funcs{}, objects...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := (&fakeGetter{r: r}).session(t)
	if reason, _ := degradedReason(got); got.Status.State != podtracev1alpha1.SessionStateFailed || reason != "TracerConfigUnresolved" {
		t.Fatalf("state = %q reason = %q, want Failed TracerConfigUnresolved", got.Status.State, reason)
	}
	var jobs batchv1.JobList
	if err := r.List(context.Background(), &jobs); err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != 0 {
		t.Errorf("%d privileged Job(s) created from a disallowed image", len(jobs.Items))
	}
}

func TestBuildDiagnoseArgs_SelectorWithNoGrantedNamespaceSelectsNothing(t *testing.T) {
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "b"}}
		s.Spec.PodRefs = []podtracev1alpha1.PodRef{{Name: "p1"}}
	})
	args := buildDiagnoseArgs(s, sessionTargets{Namespaces: []string{}, PodRefs: s.Spec.PodRefs}, time.Minute)

	for _, flag := range []string{"--pod-selector", "--all-in-namespace", "--namespace", "--namespaces"} {
		if slices.Contains(args, flag) {
			t.Errorf("args %v must not carry %s when the namespace selector granted nothing", args, flag)
		}
	}
	if i := slices.Index(args, "--pods"); i < 0 || args[i+1] != "default/p1" {
		t.Errorf("args %v must still trace the pod references", args)
	}
}

func TestBuildDiagnoseArgs_SelectorWithoutNamespaceSelectorStaysInOwnNamespace(t *testing.T) {
	s := sessMoreSession(nil)
	args := buildDiagnoseArgs(s, sessionTargets{}, time.Minute)

	if i := slices.Index(args, "--namespace"); i < 0 || args[i+1] != "default" || !slices.Contains(args, "--pod-selector") {
		t.Errorf("args %v must select in the session's own namespace", args)
	}
}

func TestPublishSessionSecretReport_MergesStagingAcrossFleetNamespaces(t *testing.T) {
	s := secretReportSession()
	other := stagedReport(s, "n2", "two")
	other.Namespace = "fleet-b"
	c := stagingClient(t, interceptor.Funcs{}, stagedReport(s, "n1", "one"), other)

	if err := publishSessionSecretReport(context.Background(), c, c, s, []string{"fleet-b", sessMoreSysNS}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	var report corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: s.Namespace, Name: "report"}, &report); err != nil {
		t.Fatal(err)
	}
	if string(report.Data["report-n1.txt"]) != "one" || string(report.Data["report-n2.txt"]) != "two" {
		t.Errorf("report data = %v, want both fleets' nodes", report.Data)
	}
}

func TestNodesAtCapacity_JobListErrorIsReturned(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*batchv1.JobList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}

	if _, err := r.nodesAtCapacity(context.Background(), []string{"n1"}, 1, "default", "s"); err == nil {
		t.Fatal("a failed session Job list must be returned")
	}
}
