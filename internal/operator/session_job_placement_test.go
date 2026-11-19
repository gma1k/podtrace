package operator

import (
	"context"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

const previousFleetNS = "old-sys"

func previousFleetConfig() *podtracev1alpha1.TracerConfig {
	return testTracerConfig("fleet-old", "ghcr.io/gma1k/podtrace:test", previousFleetNS, map[string]string{"fleet": "old"})
}

func sessionJobsOnNode(t *testing.T, c client.Client, node string) []batchv1.Job {
	t.Helper()
	var jobs batchv1.JobList
	if err := c.List(context.Background(), &jobs, client.MatchingLabels{LabelNodeName: node}); err != nil {
		t.Fatal(err)
	}
	return jobs.Items
}

func TestSessionReconcile_NodeKeepsJobAfterItsFleetMoves(t *testing.T) {
	s := fannedOutSession()
	moved := runningSessionJob(s, "n1")
	moved.Namespace = previousFleetNS
	r := revocationReconciler(t, interceptor.Funcs{}, append(sessMoreFanOutObjects()[1:], s, previousFleetConfig(), moved)...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	jobs := sessionJobsOnNode(t, r.Client, "n1")
	if len(jobs) != 1 || jobs[0].Namespace != previousFleetNS {
		t.Fatalf("node n1 has %d Job(s), want only its original Job in %s: %+v", len(jobs), previousFleetNS, jobs)
	}
	got := (&fakeGetter{r: r}).session(t)
	if len(got.Status.Jobs) != 1 || got.Status.Jobs[0].Completed {
		t.Errorf("status.jobs = %+v, want the running Job of n1", got.Status.Jobs)
	}
}

func TestSessionReconcile_WithdrawnGrantStopsJobInPreviousFleetNamespace(t *testing.T) {
	s := crossNamespaceSession()
	moved := jobTracing(s, "--namespaces", "tenant-b")
	moved.Namespace = previousFleetNS
	r := revocationReconciler(t, interceptor.Funcs{}, append(sessMoreFanOutObjects()[1:], s, previousFleetConfig(), tenantNamespace(""), moved)...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if jobs := sessionJobsOnNode(t, r.Client, "n1"); len(jobs) != 0 {
		t.Fatalf("a Job outside the namespaces resolved this pass still traces a namespace that withdrew its grant: %+v", jobs)
	}
	if got := (&fakeGetter{r: r}).session(t); got.Status.State != podtracev1alpha1.SessionStateFailed {
		t.Errorf("state = %q, want Failed", got.Status.State)
	}
}

func TestSessionReconcile_RecordedJobRemovedBeforeOutcomeIsNotRecreated(t *testing.T) {
	s := fannedOutSession()
	r := revocationReconciler(t, interceptor.Funcs{}, append(sessMoreFanOutObjects()[1:], s)...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if jobs := sessionJobsOnNode(t, r.Client, "n1"); len(jobs) != 0 {
		t.Fatalf("the removed Job of n1 was created again, tracing the node twice: %+v", jobs)
	}
	got := (&fakeGetter{r: r}).session(t)
	if len(got.Status.Jobs) != 1 || !got.Status.Jobs[0].Completed || got.Status.Jobs[0].Message != sessionJobVanishedMessage {
		t.Fatalf("status.jobs = %+v, want n1 done with %q", got.Status.Jobs, sessionJobVanishedMessage)
	}
	if got.Status.State != podtracev1alpha1.SessionStateCompleted {
		t.Errorf("state = %q, want Completed", got.Status.State)
	}
}

func TestSessionReconcile_RecordedJobMissingFromCacheIsLeftAlone(t *testing.T) {
	s := fannedOutSession()
	hidden := runningSessionJob(s, "n1")
	r := revocationReconciler(t, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*batchv1.JobList); ok {
				return nil
			}
			return c.List(ctx, list, opts...)
		},
	}, append(sessMoreFanOutObjects()[1:], s, hidden)...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var job batchv1.Job
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: sessMoreSysNS, Name: hidden.Name}, &job); err != nil {
		t.Fatalf("the live Job must stay: %v", err)
	}
	got := (&fakeGetter{r: r}).session(t)
	for _, ref := range got.Status.Jobs {
		if ref.Message == sessionJobVanishedMessage {
			t.Fatalf("a Job the API server still has must not be marked removed: %+v", ref)
		}
	}
}

func TestSessionReconcile_JobLookupErrorIsReturned(t *testing.T) {
	s := fannedOutSession()
	r := revocationReconciler(t, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*batchv1.Job); ok {
				return errInternal()
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}, append(sessMoreFanOutObjects()[1:], s)...)

	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("a failed Job lookup must surface as an error")
	}
	if jobs := sessionJobsOnNode(t, r.Client, "n1"); len(jobs) != 0 {
		t.Fatalf("no Job may be created while the lookup fails: %+v", jobs)
	}
}
