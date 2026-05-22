package operator

import (
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestObserveReportUploadMetrics_DedupesAcrossReconciles(t *testing.T) {
	reset := func() {
		forgetReportObservations("ns", "s")
		reportUploadAttempts.Reset()
		reportUploadDuration.Reset()
	}
	reset()
	defer reset()

	s := &podtracev1alpha1.PodTraceSession{}
	s.Name, s.Namespace = "s", "ns"
	s.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		ObjectStore: &podtracev1alpha1.ObjectStoreReference{URI: "s3://b/k/"},
	}
	obs := reportUploadObservation{
		ResolvedURI: "s3://b/k/r.txt",
		Terminated:  true,
		Succeeded:   true,
		Attempts:    1,
	}

	for i := 0; i < 5; i++ {
		observeReportUploadMetrics(s, obs)
	}

	if got := counterTotal(t, "s3", "success", ""); got != 1 {
		t.Errorf("dedup failed: counter = %v, want 1 after 5 identical observations", got)
	}
}

func TestObserveReportUploadMetrics_NewAttemptCountsAgain(t *testing.T) {
	reset := func() {
		forgetReportObservations("ns", "s")
		reportUploadAttempts.Reset()
	}
	reset()
	defer reset()

	s := &podtracev1alpha1.PodTraceSession{}
	s.Name, s.Namespace = "s", "ns"
	s.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		ObjectStore: &podtracev1alpha1.ObjectStoreReference{URI: "s3://b/k/"},
	}

	observeReportUploadMetrics(s, reportUploadObservation{
		ResolvedURI: "404 NoSuchBucket",
		Terminated:  true, Succeeded: false, Attempts: 1,
	})
	observeReportUploadMetrics(s, reportUploadObservation{
		ResolvedURI: "s3://b/k/r.txt",
		Terminated:  true, Succeeded: true, Attempts: 2,
	})

	if got := counterTotal(t, "s3", "failure", "BucketNotFound"); got != 1 {
		t.Errorf("first attempt failure counter = %v, want 1", got)
	}
	if got := counterTotal(t, "s3", "success", ""); got != 1 {
		t.Errorf("second attempt success counter = %v, want 1", got)
	}
}

func TestObserveReportUploadMetrics_DropsPendingAndNonObjectStore(t *testing.T) {
	reset := func() {
		forgetReportObservations("ns", "s")
		reportUploadAttempts.Reset()
	}
	reset()
	defer reset()

	pending := &podtracev1alpha1.PodTraceSession{}
	pending.Name, pending.Namespace = "s", "ns"
	pending.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		ObjectStore: &podtracev1alpha1.ObjectStoreReference{URI: "s3://b/k/"},
	}
	observeReportUploadMetrics(pending, reportUploadObservation{Terminated: false})

	cmSink := &podtracev1alpha1.PodTraceSession{}
	cmSink.Name, cmSink.Namespace = "cm", "ns"
	observeReportUploadMetrics(cmSink, reportUploadObservation{Terminated: true, Succeeded: true})

	if got := counterTotal(t, "s3", "success", ""); got != 0 {
		t.Errorf("pending observation must not contribute, got %v", got)
	}
	if got := counterTotal(t, "s3", "failure", "BucketNotFound"); got != 0 {
		t.Errorf("non-objectstore must not contribute, got %v", got)
	}
}

func TestBackendFromURI(t *testing.T) {
	cases := map[string]string{
		"s3://b/k":             "s3",
		"gs://b/k":             "gs",
		"azblob://acct/cont/k": "azblob",
		"":                     "unknown",
		"http://b/k":           "unknown",
	}
	for uri, want := range cases {
		t.Run(strings.ReplaceAll(uri, "/", "_"), func(t *testing.T) {
			if got := backendFromURI(uri); got != want {
				t.Errorf("backendFromURI(%q) = %q, want %q", uri, got, want)
			}
		})
	}
}

func counterTotal(t *testing.T, backend, result, reason string) float64 {
	t.Helper()
	m, err := reportUploadAttempts.GetMetricWithLabelValues(backend, result, reason)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues: %v", err)
	}
	var pb dto.Metric
	if err := m.Write(&pb); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return pb.GetCounter().GetValue()
}