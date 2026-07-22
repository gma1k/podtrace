package operator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func helperTestSession() *podtracev1alpha1.PodTraceSession {
	return &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a", UID: "sess-uid"},
	}
}

func TestEnsureSessionExporterBundle_RenderError(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := helperTestSession()
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "team-a"},
		Spec:       podtracev1alpha1.ExporterConfigSpec{Type: podtracev1alpha1.ExporterTypeOTLP},
	}
	if err := ensureSessionExporterBundle(context.Background(), c, s, ec, "podtrace-system"); err == nil {
		t.Fatal("an OTLP ExporterConfig with a nil OTLP block must fail bundle rendering")
	}
}

func TestEnsureSessionExporterBundle_PruneStaleSecretDeleteError(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	s := helperTestSession()
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "team-a"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4318", Protocol: podtracev1alpha1.OTLPProtocolHTTP},
		},
	}
	if err := ensureSessionExporterBundle(context.Background(), c, s, ec, "podtrace-system"); err == nil {
		t.Fatal("a failing prune of the credential-less bundle Secret must be surfaced")
	}
}

func TestEnsureSessionObjectStoreCredentials_GetError(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	s := helperTestSession()
	s.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		ObjectStore: &podtracev1alpha1.ObjectStoreReference{
			URI:                  "s3://b/k",
			CredentialsSecretRef: &corev1.LocalObjectReference{Name: "creds"},
		},
	}
	if _, err := ensureSessionObjectStoreCredentials(context.Background(), c, s, "podtrace-system"); err == nil {
		t.Fatal("a non-NotFound Get of the credentials Secret must be surfaced")
	}
}

func TestEnsureSessionObjectStoreCredentials_CreateError(t *testing.T) {
	scheme := newOperatorScheme(t)
	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "team-a"},
		Data:       map[string][]byte{"access": []byte("k")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(src).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	s := helperTestSession()
	s.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		ObjectStore: &podtracev1alpha1.ObjectStoreReference{
			URI:                  "s3://b/k",
			CredentialsSecretRef: &corev1.LocalObjectReference{Name: "creds"},
		},
	}
	if _, err := ensureSessionObjectStoreCredentials(context.Background(), c, s, "podtrace-system"); err == nil {
		t.Fatal("a failing upsert of the copied credentials Secret must be surfaced")
	}
}

func TestPopulateSessionSummaries_ReadError(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*corev1.PodList); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	s := helperTestSession()
	completed := metav1.Now()
	jobs := []batchv1.Job{{
		ObjectMeta: metav1.ObjectMeta{Name: "j1", Namespace: "podtrace-system"},
		Status:     batchv1.JobStatus{CompletionTime: &completed},
	}}
	if err := populateSessionSummaries(context.Background(), c, s, jobs); err == nil {
		t.Fatal("a failing pod list while reading a finished Job's summary must be surfaced")
	}
}

func TestSessionJobName_EmptyNodeFallsBackToHashOnly(t *testing.T) {
	name := SessionJobName("sess-uid", "")
	if name == "" {
		t.Fatal("empty node name must still yield a non-empty Job name")
	}
	if !strings.HasPrefix(name, "pts-") {
		t.Fatalf("Job name %q must retain the pts- prefix", name)
	}
	if strings.HasSuffix(name, "-") {
		t.Fatalf("Job name %q must not end in a dash", name)
	}
}

func durationSampleCount(t *testing.T, backend, result string) uint64 {
	t.Helper()
	obs, err := reportUploadDuration.GetMetricWithLabelValues(backend, result)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues: %v", err)
	}
	m, ok := obs.(prometheus.Metric)
	if !ok {
		t.Fatal("histogram observer is not a prometheus.Metric")
	}
	var pb dto.Metric
	if err := m.Write(&pb); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return pb.GetHistogram().GetSampleCount()
}

func TestObserveReportUploadMetrics_ObservesDurationWhenStarted(t *testing.T) {
	reset := func() {
		forgetReportObservations("ns-dur", "s-dur")
		reportUploadAttempts.Reset()
		reportUploadDuration.Reset()
	}
	reset()
	defer reset()

	s := &podtracev1alpha1.PodTraceSession{}
	s.Name, s.Namespace = "s-dur", "ns-dur"
	s.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		ObjectStore: &podtracev1alpha1.ObjectStoreReference{URI: "s3://b/k/"},
	}
	start := metav1.NewTime(time.Now().Add(-2 * time.Second))
	s.Status.StartTime = &start

	observeReportUploadMetrics(s, reportUploadObservation{
		ResolvedURI: "s3://b/k/r.txt",
		Terminated:  true,
		Succeeded:   true,
		Attempts:    1,
	})

	if got := durationSampleCount(t, "s3", "success"); got != 1 {
		t.Errorf("duration histogram sample count = %d, want 1 once StartTime is set", got)
	}
}
