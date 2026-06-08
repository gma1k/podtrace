package operator

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestEnsureSessionExporterBundle_ConfigMapCreateError(t *testing.T) {
	scheme := newSessionBundleScheme(t)
	ec := newOTLPExporter("prod-otlp", "team-a")
	boom := errors.New("apiserver down")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.ConfigMap); ok {
					return boom
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "sess-cm-err"},
	}
	err := ensureSessionExporterBundle(context.Background(), c, s, ec, "podtrace-system")
	if err == nil {
		t.Fatal("expected error when ConfigMap reconcile fails")
	}
	if !strings.Contains(err.Error(), "ConfigMap") {
		t.Errorf("error %q should mention ConfigMap", err.Error())
	}
}

func TestEnsureSessionExporterBundle_SecretCreateError(t *testing.T) {
	scheme := newSessionBundleScheme(t)
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "dd", Namespace: "team-a", UID: "ec-dd-secret-err"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeDataDog,
			DataDog: &podtracev1alpha1.DataDogExporter{
				APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "dd-creds", Key: "api_key"},
			},
		},
	}
	userSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "dd-creds", Namespace: "team-a"},
		Data:       map[string][]byte{"api_key": []byte("k")},
	}
	boom := errors.New("secret store unavailable")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec, userSecret).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Secret); ok && key.Namespace == "podtrace-system" {
					return boom
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "sess-secret-err"},
	}
	err := ensureSessionExporterBundle(context.Background(), c, s, ec, "podtrace-system")
	if err == nil {
		t.Fatal("expected error when companion Secret reconcile fails")
	}
	if !strings.Contains(err.Error(), "Secret") {
		t.Errorf("error %q should mention Secret", err.Error())
	}
}

func TestEnsureSessionExporterBundle_MissingCredentialSecretErrors(t *testing.T) {
	scheme := newSessionBundleScheme(t)
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "dd", Namespace: "team-a", UID: "ec-dd-missing"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeDataDog,
			DataDog: &podtracev1alpha1.DataDogExporter{
				APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "absent-secret", Key: "api_key"},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec).Build()

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "sess-missing-cred"},
	}
	err := ensureSessionExporterBundle(context.Background(), c, s, ec, "podtrace-system")
	if err == nil {
		t.Fatal("expected error when credential Secret is absent")
	}
	if !strings.Contains(err.Error(), "credential") {
		t.Errorf("error %q should mention credential", err.Error())
	}
}

func TestLoadCredentialSecret_MissingKeyErrors(t *testing.T) {
	scheme := newSessionBundleScheme(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "team-a"},
		Data:       map[string][]byte{"wrong_key": []byte("x")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	_, err := loadCredentialSecret(context.Background(), c, "team-a",
		podtracev1alpha1.SecretKeySelector{Name: "creds", Key: "api_key"})
	if err == nil {
		t.Fatal("expected error when referenced key is absent")
	}
	if !strings.Contains(err.Error(), "api_key") {
		t.Errorf("error %q should name the missing key", err.Error())
	}
}
