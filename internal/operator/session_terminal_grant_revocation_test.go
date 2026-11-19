package operator

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func failedSessionWithRunningSibling() *podtracev1alpha1.PodTraceSession {
	s := crossNamespaceSession()
	completed := metav1.Now()
	s.Status.State = podtracev1alpha1.SessionStateFailed
	s.Status.CompletionTime = &completed
	return s
}

func sessionReconciledReason(s podtracev1alpha1.PodTraceSession) (string, string) {
	for _, cond := range s.Status.Conditions {
		if cond.Type == ConditionReconciled {
			return cond.Reason, cond.Message
		}
	}
	return "", ""
}

func TestTerminalSession_WithdrawnGrantStopsJobStillRunning(t *testing.T) {
	s := failedSessionWithRunningSibling()
	objects := []client.Object{s, tenantNamespace(""), jobTracing(s, "--namespaces", "tenant-b")}
	objects = append(objects, podReadGrant(s, "tenant-b")...)
	r := revocationReconciler(t, interceptor.Funcs{}, objects...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if sessionJobExists(t, r.Client, s) {
		t.Fatal("a terminal session's Job tracing a namespace that withdrew its grant must be stopped")
	}
	if left := podReadGrantLeft(t, r.Client, "tenant-b"); left != 0 {
		t.Errorf("%d pod-read RBAC object(s) left in the namespace that withdrew its grant", left)
	}
	got := (&fakeGetter{r: r}).session(t)
	if got.Status.State != podtracev1alpha1.SessionStateFailed {
		t.Errorf("state = %q, want it to stay Failed", got.Status.State)
	}
	if reason, message := sessionReconciledReason(got); reason != "CrossNamespaceGrantRevoked" || !strings.Contains(message, "[tenant-b]") {
		t.Errorf("Reconciled = %s: %q, want CrossNamespaceGrantRevoked naming tenant-b", reason, message)
	}
}

func TestTerminalSession_RunningJobWithGrantKeepsPolling(t *testing.T) {
	s := failedSessionWithRunningSibling()
	r := revocationReconciler(t, interceptor.Funcs{}, s, tenantNamespace("default"), jobTracing(s, "--namespaces", "tenant-b"))

	res, err := sessMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !sessionJobExists(t, r.Client, s) {
		t.Fatal("a Job whose namespaces still grant the session must keep running")
	}
	if res.RequeueAfter != terminalSessionJobPoll {
		t.Errorf("RequeueAfter = %s, want %s while a Job still runs", res.RequeueAfter, terminalSessionJobPoll)
	}
}

func TestTerminalSession_NoRunningJobWaitsForTTL(t *testing.T) {
	s := failedSessionWithRunningSibling()
	job := jobTracing(s, "--namespaces", "tenant-b")
	job.Status.Succeeded = 1
	r := revocationReconciler(t, interceptor.Funcs{}, s, tenantNamespace(""), job)

	res, err := sessMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !sessionJobExists(t, r.Client, s) {
		t.Fatal("a finished Job is left for its TTL, not deleted")
	}
	if res.RequeueAfter <= terminalSessionJobPoll {
		t.Errorf("RequeueAfter = %s, want the session TTL once no Job runs", res.RequeueAfter)
	}
}

func TestTerminalSession_TracerConfigListErrorIsReturned(t *testing.T) {
	s := failedSessionWithRunningSibling()
	r := revocationReconciler(t, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*podtracev1alpha1.TracerConfigList); ok {
				return errInternal()
			}
			return c.List(ctx, list, opts...)
		},
	}, s)

	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("a failed TracerConfig list must surface as an error")
	}
}
