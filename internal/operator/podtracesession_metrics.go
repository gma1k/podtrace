package operator

import (
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	"github.com/podtrace/podtrace/internal/reportsink/objectstore"
)

// Session-objectStore Prometheus surface.
var (
	reportUploadAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "podtrace_operator",
		Name:      "session_report_upload_attempts_total",
		Help: "Terminal outcomes of the objectStore uploader sidecar. " +
			"backend ∈ {s3,gs,azblob}, result ∈ {success,failure}, " +
			"reason ∈ ReportFailureReason enum (empty when result=success). " +
			"Compare rate(result=failure) vs rate(result=success) for an SLO; " +
			"sum by (reason) to find the dominant failure mode.",
	}, []string{"backend", "result", "reason"})

	reportUploadDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "podtrace_operator",
		Name:      "session_report_upload_duration_seconds",
		Help: "Time from session start to terminal objectStore sidecar outcome. " +
			"Buckets sized for typical small reports (under 100KB) with headroom " +
			"for occasional slow tails. Use histogram_quantile(0.95, …) to track " +
			"the long tail.",
		Buckets: []float64{0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300, 600},
	}, []string{"backend", "result"})

	observed = struct {
		sync.Mutex
		seen map[reportObservationKey]struct{}
	}{seen: map[reportObservationKey]struct{}{}}
)

type reportObservationKey struct {
	Namespace string
	Name      string
	Attempts  int32
	Succeeded bool
}

func init() {
	ctrlmetrics.Registry.MustRegister(reportUploadAttempts, reportUploadDuration)
}

// observeReportUploadMetrics records one Prometheus observation per
// terminal sidecar outcome. Safe to call on every reconcile: it
// deduplicates against (namespace/name/attempts/succeeded) so repeated
// calls for the same outcome only count once.
func observeReportUploadMetrics(s *podtracev1alpha1.PodTraceSession, obs reportUploadObservation) {
	if s == nil || s.Spec.ReportRef == nil || s.Spec.ReportRef.ObjectStore == nil {
		return
	}
	if !obs.Terminated {
		return
	}
	key := reportObservationKey{
		Namespace: s.Namespace,
		Name:      s.Name,
		Attempts:  obs.Attempts,
		Succeeded: obs.Succeeded,
	}
	observed.Lock()
	if _, alreadyCounted := observed.seen[key]; alreadyCounted {
		observed.Unlock()
		return
	}
	observed.seen[key] = struct{}{}
	observed.Unlock()

	backend := backendFromURI(s.Spec.ReportRef.ObjectStore.URI)
	result := "success"
	reason := ""
	if !obs.Succeeded {
		result = "failure"
		reason = string(classifyUploadFailure(obs.ResolvedURI))
	}
	reportUploadAttempts.WithLabelValues(backend, result, reason).Inc()

	if duration := uploadDurationSeconds(s); duration > 0 {
		reportUploadDuration.WithLabelValues(backend, result).Observe(duration)
	}
}

// forgetReportObservations clears the dedup-set for a session when
// the operator garbage-collects it. Bounded-memory hygiene so a
// long-running operator does not retain entries for thousands of
// completed sessions forever.
func forgetReportObservations(namespace, name string) {
	observed.Lock()
	defer observed.Unlock()
	for k := range observed.seen {
		if k.Namespace == namespace && k.Name == name {
			delete(observed.seen, k)
		}
	}
}

// backendFromURI extracts the scheme prefix for use as a metric
// label. Falls back to "unknown" for malformed URIs so the label
// cardinality stays bounded to the supported scheme set + 1.
func backendFromURI(uri string) string {
	switch {
	case strings.HasPrefix(uri, objectstore.SchemeS3+"://"):
		return objectstore.SchemeS3
	case strings.HasPrefix(uri, objectstore.SchemeGCS+"://"):
		return objectstore.SchemeGCS
	case strings.HasPrefix(uri, objectstore.SchemeAzure+"://"):
		return objectstore.SchemeAzure
	default:
		return "unknown"
	}
}

// uploadDurationSeconds returns the wall-clock seconds between
// status.startTime and now for the duration histogram.
func uploadDurationSeconds(s *podtracev1alpha1.PodTraceSession) float64 {
	if s.Status.StartTime == nil {
		return 0
	}
	return time.Since(s.Status.StartTime.Time).Seconds()
}
