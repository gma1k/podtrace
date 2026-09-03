package agent

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func enqueueFor(t *testing.T, plane MetricsPlaneConfig, podTraces ...*podtracev1alpha1.PodTrace) int {
	t.Helper()

	builder := fake.NewClientBuilder().WithScheme(newScheme(t))
	for _, pt := range podTraces {
		builder = builder.WithObjects(pt)
	}

	r := &AgentReconciler{Client: builder.Build(), MetricsPlane: plane}
	return len(r.enqueueAllPodTraces(context.Background(), &corev1.Pod{}))
}

func TestPodEventEnqueuesNothingWithoutCRsOrPlane(t *testing.T) {
	if got := enqueueFor(t, MetricsPlaneConfig{Enabled: false}); got != 0 {
		t.Errorf("got %d requests, want 0", got)
	}
}

func TestPodEventStillReconcilesWhenPlaneIsOnAndNoCRExists(t *testing.T) {
	got := enqueueFor(t, MetricsPlaneConfig{Enabled: true})
	if got != 1 {
		t.Fatalf("got %d requests, want 1; the agent's controller is built "+
			"For(&PodTrace{}) and maps pod events through the PodTrace list, so with "+
			"no CR authored a pod event enqueues nothing and coverage-by-default "+
			"never engages", got)
	}
}

func TestPlaneRequestIsAdditiveToRealCRRequests(t *testing.T) {
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "one"},
	}

	withoutPlane := enqueueFor(t, MetricsPlaneConfig{Enabled: false}, pt)
	withPlane := enqueueFor(t, MetricsPlaneConfig{Enabled: true}, pt)

	if withoutPlane != 1 {
		t.Fatalf("got %d requests for one CR, want 1", withoutPlane)
	}
	if withPlane != 2 {
		t.Errorf("got %d requests with the plane on, want 2; the plane's refresh "+
			"must be added to the CR requests, not replace them", withPlane)
	}
}

func TestPlaneRequestCannotCollideWithARealPodTrace(t *testing.T) {
	name := metricsPlaneRequest.Name
	if errs := apivalidation.NameIsDNSSubdomain(name, false); len(errs) == 0 {
		t.Errorf("%q is a valid object name, so a real PodTrace could take it and "+
			"the two reconcile paths would alias", name)
	}
}
