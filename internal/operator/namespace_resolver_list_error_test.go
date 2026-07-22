package operator

import (
	"context"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestResolveNamespaceSelector_ListError(t *testing.T) {
	scheme, err := NewScheme()
	if err != nil {
		t.Fatalf("scheme: %v", err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return apierrors.NewInternalError(errors.New("synthetic namespace list failure"))
		},
	}).Build()

	allowed, denied, err := ResolveNamespaceSelector(context.Background(), c,
		&metav1.LabelSelector{MatchLabels: map[string]string{"tier": "prod"}}, "observer")
	if err == nil {
		t.Fatal("expected error when namespace List fails")
	}
	if allowed != nil || denied != nil {
		t.Errorf("expected nil result slices on error, got allowed=%v denied=%v", allowed, denied)
	}
}
