package operator

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type uploaderState int

const (
	uploaderRunning uploaderState = iota
	uploaderSucceeded
	uploaderFailed
	uploaderNoStatus
)

func nodeUploaderPod(namespace, name, node string, state uploaderState, message string, created time.Time) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         namespace,
			CreationTimestamp: metav1.NewTime(created),
			Labels: map[string]string{
				LabelSessionName: "diag",
				LabelSessionNS:   "default",
				LabelNodeName:    node,
			},
		},
		Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: reportUploaderContainerName}}},
	}
	status := corev1.ContainerStatus{Name: reportUploaderContainerName, RestartCount: 1}
	switch state {
	case uploaderNoStatus:
		return pod
	case uploaderRunning:
		status.State.Running = &corev1.ContainerStateRunning{}
	case uploaderSucceeded:
		status.State.Terminated = &corev1.ContainerStateTerminated{ExitCode: 0, Message: message}
	case uploaderFailed:
		status.State.Terminated = &corev1.ContainerStateTerminated{ExitCode: 1, Message: message}
	}
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{status}
	return pod
}

func harvestAcross(t *testing.T, pods ...client.Object) reportUploadObservation {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(harvestScheme(t)).WithObjects(pods...).Build()
	obs, err := harvestReportLocation(context.Background(), c, sessionWithObjectStore(""), []string{"fleet-a", "fleet-b"})
	if err != nil {
		t.Fatalf("harvest: %v", err)
	}
	return obs
}

func TestHarvestReportLocation_FailureOnAnyNodeWins(t *testing.T) {
	start := time.Now()
	obs := harvestAcross(t,
		nodeUploaderPod("fleet-a", "pa", "a", uploaderSucceeded, "s3://b/reports/a.txt", start),
		nodeUploaderPod("fleet-b", "pb", "b", uploaderFailed, "AccessDenied", start),
	)
	if !obs.Terminated || obs.Succeeded {
		t.Fatalf("obs = %+v, want a failed upload when one node failed", obs)
	}
	if obs.ResolvedURI != "node b: AccessDenied" {
		t.Errorf("message = %q, want the failing node named", obs.ResolvedURI)
	}
}

func TestHarvestReportLocation_SucceedsOnlyWhenEveryNodeSucceeded(t *testing.T) {
	start := time.Now()
	obs := harvestAcross(t,
		nodeUploaderPod("fleet-b", "pb", "b", uploaderSucceeded, "s3://b/reports/b.txt", start),
		nodeUploaderPod("fleet-a", "pa", "a", uploaderSucceeded, "s3://b/reports/a.txt", start),
	)
	if !obs.Terminated || !obs.Succeeded || obs.ResolvedURI != "s3://b/reports/a.txt" {
		t.Errorf("obs = %+v, want success with the first node's object", obs)
	}
}

func TestHarvestReportLocation_PendingWhileAnyNodeUploads(t *testing.T) {
	start := time.Now()
	for name, state := range map[string]uploaderState{"running": uploaderRunning, "no status yet": uploaderNoStatus} {
		t.Run(name, func(t *testing.T) {
			obs := harvestAcross(t,
				nodeUploaderPod("fleet-a", "pa", "a", uploaderSucceeded, "s3://b/reports/a.txt", start),
				nodeUploaderPod("fleet-b", "pb", "b", state, "", start),
			)
			if obs.Terminated || obs.Succeeded || obs.UploaderDisabled {
				t.Errorf("obs = %+v, want pending while node b has not finished", obs)
			}
		})
	}
}

func TestHarvestReportLocation_UsesLatestPodPerNode(t *testing.T) {
	start := time.Now()
	obs := harvestAcross(t,
		nodeUploaderPod("fleet-a", "pa-retry", "a", uploaderSucceeded, "s3://b/reports/a.txt", start.Add(time.Minute)),
		nodeUploaderPod("fleet-a", "pa-first", "a", uploaderFailed, "timeout", start),
	)
	if !obs.Succeeded {
		t.Errorf("obs = %+v, want the retried pod's success to replace the first attempt", obs)
	}
}

func TestHarvestReportLocation_SingleNodeFailureKeepsRawMessage(t *testing.T) {
	obs := harvestAcross(t, nodeUploaderPod("fleet-b", "pb", "b", uploaderFailed, "NoSuchBucket", time.Now()))
	if obs.ResolvedURI != "NoSuchBucket" {
		t.Errorf("message = %q, want the sidecar's message unchanged for a one-node session", obs.ResolvedURI)
	}
}

func TestHarvestReportLocation_KeepsNewerPodListedFirst(t *testing.T) {
	start := time.Now()
	obs := harvestAcross(t,
		nodeUploaderPod("fleet-a", "pa-a", "a", uploaderSucceeded, "s3://b/reports/a.txt", start.Add(time.Minute)),
		nodeUploaderPod("fleet-a", "pa-b", "a", uploaderFailed, "timeout", start),
	)
	if !obs.Succeeded {
		t.Errorf("obs = %+v, want the newer pod kept over an older one listed after it", obs)
	}
}
