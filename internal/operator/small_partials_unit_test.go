package operator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// ─── runtime.go NewScheme ─────────────────────────────────────────────

func TestSmall_NewScheme_RegistersPodtraceTypes(t *testing.T) {
	s, err := NewScheme()
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}
	if s == nil {
		t.Fatal("NewScheme returned nil scheme")
	}
	gvk := podtracev1alpha1.GroupVersion.WithKind("PodTrace")
	if !s.Recognizes(gvk) {
		t.Errorf("scheme does not recognize %v", gvk)
	}
	if len(s.AllKnownTypes()) == 0 {
		t.Error("scheme has no known types")
	}
}

// ─── podtraceschedule_controller.go now ───────────────────────────────

func TestSmall_ScheduleReconciler_Now(t *testing.T) {
	r := &PodTraceScheduleReconciler{}
	before := time.Now()
	got := r.now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Errorf("now() = %v, want within [%v, %v]", got, before, after)
	}

	pinned := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	r.nowFn = func() time.Time { return pinned }
	if g := r.now(); !g.Equal(pinned) {
		t.Errorf("now() = %v, want pinned %v", g, pinned)
	}
}

// ─── podtraceschedule_controller.go keyFor ────────────────────────────

func TestSmall_ScheduleReconciler_KeyFor(t *testing.T) {
	completion := metav1.NewTime(time.Date(2026, 6, 8, 10, 0, 0, 0, time.UTC))
	creation := metav1.NewTime(time.Date(2026, 6, 7, 9, 0, 0, 0, time.UTC))

	withCompletion := podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{CreationTimestamp: creation},
		Status:     podtracev1alpha1.PodTraceSessionStatus{CompletionTime: &completion},
	}
	if got := keyFor(withCompletion); !got.Equal(completion.Time) {
		t.Errorf("keyFor(withCompletion) = %v, want %v", got, completion.Time)
	}

	noCompletion := podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{CreationTimestamp: creation},
	}
	if got := keyFor(noCompletion); !got.Equal(creation.Time) {
		t.Errorf("keyFor(noCompletion) = %v, want %v", got, creation.Time)
	}
}

// ─── podtraceschedule_controller.go applyHistoryLimits ────────────────

func TestSmall_ScheduleReconciler_ApplyHistoryLimits(t *testing.T) {
	r := &PodTraceScheduleReconciler{
		Client: fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).Build(),
		Scheme: newOperatorScheme(t),
	}
	ctx := context.Background()

	bare := &podtracev1alpha1.PodTraceSchedule{}
	if err := r.applyHistoryLimits(ctx, bare, nil, nil); err != nil {
		t.Fatalf("applyHistoryLimits(both nil) = %v", err)
	}

	limit := int32(0)
	failedOnly := &podtracev1alpha1.PodTraceSchedule{
		Spec: podtracev1alpha1.PodTraceScheduleSpec{FailedSessionsHistoryLimit: &limit},
	}
	if err := r.applyHistoryLimits(ctx, failedOnly, nil, nil); err != nil {
		t.Fatalf("applyHistoryLimits(failed only) = %v", err)
	}

	both := &podtracev1alpha1.PodTraceSchedule{
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			SuccessfulSessionsHistoryLimit: &limit,
			FailedSessionsHistoryLimit:     &limit,
		},
	}
	if err := r.applyHistoryLimits(ctx, both, nil, nil); err != nil {
		t.Fatalf("applyHistoryLimits(both set) = %v", err)
	}
}

// ─── podtracesession_metrics.go uploadDurationSeconds ─────────────────

func TestSmall_UploadDurationSeconds(t *testing.T) {
	noStart := &podtracev1alpha1.PodTraceSession{}
	if got := uploadDurationSeconds(noStart); got != 0 {
		t.Errorf("uploadDurationSeconds(no start) = %v, want 0", got)
	}

	start := metav1.NewTime(time.Now().Add(-2 * time.Second))
	withStart := &podtracev1alpha1.PodTraceSession{
		Status: podtracev1alpha1.PodTraceSessionStatus{StartTime: &start},
	}
	if got := uploadDurationSeconds(withStart); got <= 0 {
		t.Errorf("uploadDurationSeconds(past start) = %v, want > 0", got)
	}

	reportUploadDuration.Reset()
	defer reportUploadDuration.Reset()
	obs, err := reportUploadDuration.GetMetricWithLabelValues("s3", "success")
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues: %v", err)
	}
	obs.Observe(uploadDurationSeconds(withStart))
	collector, ok := obs.(prometheus.Metric)
	if !ok {
		t.Fatal("histogram observer is not a prometheus.Metric")
	}
	var pb dto.Metric
	if err := collector.Write(&pb); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if pb.GetHistogram().GetSampleCount() != 1 {
		t.Errorf("histogram sample count = %d, want 1", pb.GetHistogram().GetSampleCount())
	}
}

// ─── session_bundle.go marshalBundleToYAML ────────────────────────────

func TestSmall_MarshalBundleToYAML(t *testing.T) {
	out, err := marshalBundleToYAML(map[string]string{
		"type":     "otlp",
		"endpoint": "collector:4317",
		"protocol": "grpc",
	})
	if err != nil {
		t.Fatalf("marshalBundleToYAML(valid) = %v", err)
	}
	if !strings.Contains(out, "collector:4317") {
		t.Errorf("YAML output missing endpoint, got:\n%s", out)
	}

	if _, err := marshalBundleToYAML(nil); err == nil {
		t.Error("marshalBundleToYAML(nil) = nil error, want error")
	}
}

// ─── session_bundle.go loadCredentialSecret ───────────────────────────

func TestSmall_LoadCredentialSecret(t *testing.T) {
	ctx := context.Background()
	ref := podtracev1alpha1.SecretKeySelector{Name: "creds", Key: "token"}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "ns"},
		Data:       map[string][]byte{"token": []byte("s3cr3t")},
	}

	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(secret).Build()
	data, err := loadCredentialSecret(ctx, c, "ns", ref)
	if err != nil {
		t.Fatalf("loadCredentialSecret(found) = %v", err)
	}
	if string(data["credential"]) != "s3cr3t" {
		t.Errorf("credential = %q, want %q", data["credential"], "s3cr3t")
	}

	noKey := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "ns"},
		Data:       map[string][]byte{"other": []byte("x")},
	}
	cNoKey := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(noKey).Build()
	if _, err := loadCredentialSecret(ctx, cNoKey, "ns", ref); err == nil {
		t.Error("loadCredentialSecret(missing key) = nil error, want error")
	}

	cEmpty := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).Build()
	if _, err := loadCredentialSecret(ctx, cEmpty, "ns", ref); err == nil {
		t.Error("loadCredentialSecret(not found) = nil error, want error")
	}
}

// ─── bootstrap.go Start ───────────────────────────────────────────────

func TestSmall_Bootstrap_Start(t *testing.T) {
	ctx := context.Background()

	existing := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}
	cExisting := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(existing).Build()
	b := &BootstrapDefaultTracerConfig{Client: cExisting, SystemNamespace: "podtrace-system"}
	if err := b.Start(ctx); err != nil {
		t.Fatalf("Start(existing) = %v", err)
	}

	t.Setenv(BootstrapImageEnv, "")
	cEmpty := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).Build()
	bNoImage := &BootstrapDefaultTracerConfig{Client: cEmpty, SystemNamespace: "podtrace-system"}
	if err := bNoImage.Start(ctx); err != nil {
		t.Fatalf("Start(no image) = %v", err)
	}

	cCreate := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).Build()
	bCreate := &BootstrapDefaultTracerConfig{
		Client:          cCreate,
		SystemNamespace: "podtrace-system",
		FallbackImage:   "ghcr.io/gma1k/podtrace:test",
	}
	if err := bCreate.Start(ctx); err != nil {
		t.Fatalf("Start(create) = %v", err)
	}
	var created podtracev1alpha1.TracerConfig
	if err := cCreate.Get(ctx, types.NamespacedName{Name: DefaultTracerConfigName}, &created); err != nil {
		t.Fatalf("expected created TracerConfig: %v", err)
	}
	if created.Spec.Image != "ghcr.io/gma1k/podtrace:test" {
		t.Errorf("created image = %q, want fallback", created.Spec.Image)
	}

	cListErr := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return errors.New("list boom")
			},
		}).Build()
	bListErr := &BootstrapDefaultTracerConfig{Client: cListErr, SystemNamespace: "podtrace-system"}
	if err := bListErr.Start(ctx); err != nil {
		t.Fatalf("Start(list error) = %v, want nil (skip)", err)
	}

	cAlready := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.CreateOption) error {
				return apierrors.NewAlreadyExists(
					podtracev1alpha1.GroupVersion.WithResource("tracerconfigs").GroupResource(),
					DefaultTracerConfigName)
			},
		}).Build()
	bAlready := &BootstrapDefaultTracerConfig{
		Client:          cAlready,
		SystemNamespace: "podtrace-system",
		FallbackImage:   "ghcr.io/gma1k/podtrace:test",
	}
	if err := bAlready.Start(ctx); err != nil {
		t.Fatalf("Start(already exists) = %v, want nil (defer)", err)
	}

	cCreateErr := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.CreateOption) error {
				return errors.New("create boom")
			},
		}).Build()
	bCreateErr := &BootstrapDefaultTracerConfig{
		Client:          cCreateErr,
		SystemNamespace: "podtrace-system",
		FallbackImage:   "ghcr.io/gma1k/podtrace:test",
	}
	if err := bCreateErr.Start(ctx); err == nil {
		t.Error("Start(create error) = nil, want wrapped error")
	}
}
