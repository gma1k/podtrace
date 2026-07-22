package operator

import (
	"context"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNodesAtCapacity_JobWithoutNodeLabelIgnored(t *testing.T) {
	const ns = "team-a"
	scheme := newOperatorScheme(t)

	labelled := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "labelled",
			Namespace: "podtrace-system",
			Labels: map[string]string{
				LabelManagedBy:   ManagedByValue,
				LabelComponent:   ComponentSession,
				LabelSessionName: "other",
				LabelSessionNS:   ns,
				LabelNodeName:    "n1",
			},
		},
	}
	unlabelled := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-node-label",
			Namespace: "podtrace-system",
			Labels: map[string]string{
				LabelManagedBy:   ManagedByValue,
				LabelComponent:   ComponentSession,
				LabelSessionName: "other",
				LabelSessionNS:   ns,
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(labelled, unlabelled).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	over, err := r.nodesAtCapacity(context.Background(), []string{"n1"}, 1, ns, "self")
	if err != nil {
		t.Fatalf("nodesAtCapacity: %v", err)
	}
	if len(over) != 1 || over[0] != "n1" {
		t.Errorf("expected n1 over capacity from the labelled Job only, got %v", over)
	}
}
