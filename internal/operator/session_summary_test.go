package operator

import (
	"context"
	"encoding/json"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func newSummaryScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = batchv1.AddToScheme(s)
	_ = podtracev1alpha1.AddToScheme(s)
	return s
}

func podWithTerminationSummary(name, ns, jobName string, summary sessionSummaryJSON) *corev1.Pod {
	raw, _ := json.Marshal(summary)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{"job-name": jobName},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "podtrace",
				State: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						Message: string(raw),
					},
				},
			}},
		},
	}
}

func TestPopulateSessionSummaries_AggregatesAcrossNodes(t *testing.T) {
	scheme := newSummaryScheme(t)
	now := metav1.Now()

	jobA := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pts-s1-a", Namespace: "podtrace-system",
			Labels: map[string]string{LabelNodeName: "node-a"},
		},
		Status: batchv1.JobStatus{Succeeded: 1, CompletionTime: &now},
	}
	jobB := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pts-s1-b", Namespace: "podtrace-system",
			Labels: map[string]string{LabelNodeName: "node-b"},
		},
		Status: batchv1.JobStatus{Succeeded: 1, CompletionTime: &now},
	}
	podA := podWithTerminationSummary("pts-s1-a-xyz", "podtrace-system", "pts-s1-a",
		sessionSummaryJSON{TotalEvents: 100, DNSEvents: 30, NetEvents: 40, Node: "node-a"})
	podB := podWithTerminationSummary("pts-s1-b-xyz", "podtrace-system", "pts-s1-b",
		sessionSummaryJSON{TotalEvents: 50, DNSEvents: 10, FSEvents: 20, ErrorsDetected: 2, Node: "node-b"})

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(podA, podB).Build()

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "team-a"},
		Status: podtracev1alpha1.PodTraceSessionStatus{
			Jobs: []podtracev1alpha1.SessionJobRef{
				{Node: "node-a", Name: "pts-s1-a"},
				{Node: "node-b", Name: "pts-s1-b"},
			},
		},
	}

	if err := populateSessionSummaries(context.Background(), c, s, []batchv1.Job{jobA, jobB}); err != nil {
		t.Fatal(err)
	}

	if got := s.Status.Jobs[0].EventCount; got != 100 {
		t.Errorf("node-a EventCount=%d want 100", got)
	}
	if got := s.Status.Jobs[1].EventCount; got != 50 {
		t.Errorf("node-b EventCount=%d want 50", got)
	}
	if s.Status.Summary == nil {
		t.Fatal("Summary not populated")
	}
	if s.Status.Summary.TotalEvents != 150 {
		t.Errorf("TotalEvents=%d want 150", s.Status.Summary.TotalEvents)
	}
	if s.Status.Summary.DNSEvents != 40 {
		t.Errorf("DNSEvents=%d want 40", s.Status.Summary.DNSEvents)
	}
	if s.Status.Summary.ErrorsDetected != 2 {
		t.Errorf("ErrorsDetected=%d want 2", s.Status.Summary.ErrorsDetected)
	}
}

func TestPopulateSessionSummaries_UnfinishedJobsContributeZero(t *testing.T) {
	scheme := newSummaryScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	running := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pts-running", Namespace: "podtrace-system",
			Labels: map[string]string{LabelNodeName: "node-x"},
		},
		Status: batchv1.JobStatus{Active: 1},
	}
	s := &podtracev1alpha1.PodTraceSession{
		Status: podtracev1alpha1.PodTraceSessionStatus{
			Jobs: []podtracev1alpha1.SessionJobRef{{Node: "node-x", Name: "pts-running"}},
		},
	}
	if err := populateSessionSummaries(context.Background(), c, s, []batchv1.Job{running}); err != nil {
		t.Fatal(err)
	}
	if s.Status.Summary != nil {
		t.Errorf("unfinished jobs should leave Summary nil: %+v", s.Status.Summary)
	}
	if s.Status.Jobs[0].EventCount != 0 {
		t.Errorf("EventCount=%d want 0", s.Status.Jobs[0].EventCount)
	}
}

func TestPopulateSessionSummaries_NodeFromSummaryAndSkipsForeignContainers(t *testing.T) {
	scheme := newSummaryScheme(t)
	now := metav1.Now()

	job := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pts-nolabel", Namespace: "podtrace-system",
		},
		Status: batchv1.JobStatus{Succeeded: 1, CompletionTime: &now},
	}
	raw, _ := json.Marshal(sessionSummaryJSON{TotalEvents: 77, Node: "node-from-summary"})
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pts-nolabel-xyz",
			Namespace: "podtrace-system",
			Labels:    map[string]string{"job-name": "pts-nolabel"},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "istio-proxy",
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{Message: "ignored"},
					},
				},
				{
					Name: "podtrace",
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{Message: string(raw)},
					},
				},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()

	s := &podtracev1alpha1.PodTraceSession{
		Status: podtracev1alpha1.PodTraceSessionStatus{
			Jobs: []podtracev1alpha1.SessionJobRef{{Node: "node-from-summary", Name: "pts-nolabel"}},
		},
	}
	if err := populateSessionSummaries(context.Background(), c, s, []batchv1.Job{job}); err != nil {
		t.Fatalf("populateSessionSummaries: %v", err)
	}
	if s.Status.Jobs[0].EventCount != 77 {
		t.Errorf("EventCount=%d want 77 (node resolved from summary.Node)", s.Status.Jobs[0].EventCount)
	}
	if s.Status.Summary == nil || s.Status.Summary.TotalEvents != 77 {
		t.Errorf("Summary not aggregated: %+v", s.Status.Summary)
	}
}

func TestPopulateSessionSummaries_NilSessionIsNoop(t *testing.T) {
	scheme := newSummaryScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	if err := populateSessionSummaries(context.Background(), c, nil, nil); err != nil {
		t.Errorf("nil session should be a no-op, got %v", err)
	}
}

func TestPopulateSessionSummaries_MalformedMessageIsNonFatal(t *testing.T) {
	scheme := newSummaryScheme(t)
	now := metav1.Now()
	job := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pts-bad", Namespace: "podtrace-system",
			Labels: map[string]string{LabelNodeName: "node-q"},
		},
		Status: batchv1.JobStatus{Succeeded: 1, CompletionTime: &now},
	}
	bad := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pts-bad-xyz",
			Namespace: "podtrace-system",
			Labels:    map[string]string{"job-name": "pts-bad"},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "podtrace",
				State: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{Message: "not json"},
				},
			}},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bad).Build()

	s := &podtracev1alpha1.PodTraceSession{
		Status: podtracev1alpha1.PodTraceSessionStatus{
			Jobs: []podtracev1alpha1.SessionJobRef{{Node: "node-q", Name: "pts-bad"}},
		},
	}
	if err := populateSessionSummaries(context.Background(), c, s, []batchv1.Job{job}); err != nil {
		t.Fatalf("malformed message should not error: %v", err)
	}
	if s.Status.Jobs[0].EventCount != 0 {
		t.Errorf("EventCount=%d want 0", s.Status.Jobs[0].EventCount)
	}
}
