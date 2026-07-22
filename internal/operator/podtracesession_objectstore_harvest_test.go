package operator

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func harvestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := podtracev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("podtrace scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1 scheme: %v", err)
	}
	return scheme
}

func TestHarvestReportLocation_ListError(t *testing.T) {
	scheme := harvestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return apierrors.NewInternalError(errors.New("synthetic list failure"))
		},
	}).Build()

	if _, err := harvestReportLocation(context.Background(), c, sessionWithObjectStore(""), "podtrace-system"); err == nil {
		t.Fatal("expected error when listing session pods fails")
	}
}

func TestHarvestReportLocation_SkipsNonUploaderAndTracksRestarts(t *testing.T) {
	scheme := harvestScheme(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "diag-pod",
			Namespace: "podtrace-system",
			Labels: map[string]string{
				LabelSessionName: "diag",
				LabelSessionNS:   "default",
			},
		},
		Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{
				{
					Name:  "unrelated-init",
					State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
				},
				{
					Name:         reportUploaderContainerName,
					RestartCount: 3,
					State:        corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
				},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()

	obs, err := harvestReportLocation(context.Background(), c, sessionWithObjectStore(""), "podtrace-system")
	if err != nil {
		t.Fatalf("harvest: %v", err)
	}
	if obs.Attempts != 3 {
		t.Errorf("Attempts = %d, want 3 (highest restart count of the uploader)", obs.Attempts)
	}
	if obs.Terminated {
		t.Error("Terminated must stay false while the uploader is still running")
	}
	if obs.Succeeded || obs.ResolvedURI != "" {
		t.Errorf("running uploader must not report success: %+v", obs)
	}
}
