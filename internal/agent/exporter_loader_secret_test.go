package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/podtrace/podtrace/internal/operator"
	"github.com/podtrace/podtrace/pkg/exporter/bundle"
)

func TestLoadBundle_SecretHeadersDecoded(t *testing.T) {
	const systemNS = "podtrace-system"
	uid := types.UID("e8c32c91-0000-0000-0000-0000000000aa")
	name := operator.ExporterBundleName(uid)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS, ResourceVersion: "5"},
		Data:       map[string]string{"type": "otlp", "endpoint": "otel:4318"},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS, ResourceVersion: "2"},
		Data: map[string][]byte{
			bundle.CredentialKey:                      []byte("tok"),
			bundle.SecretHeaderKeyPrefix + "X-Scope":  []byte("team-a"),
			bundle.SecretHeaderKeyPrefix + "X-Tenant": []byte("acme"),
			bundle.SecretHeaderKeyPrefix:              []byte("ignored-empty-suffix"),
			"unrelated":                               []byte("skip"),
		},
	}

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm, secret).Build()

	payload, err := LoadBundle(context.Background(), c, systemNS, uid)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if payload.SecretHeaders["X-Scope"] != "team-a" {
		t.Errorf("SecretHeaders[X-Scope] = %q, want team-a", payload.SecretHeaders["X-Scope"])
	}
	if payload.SecretHeaders["X-Tenant"] != "acme" {
		t.Errorf("SecretHeaders[X-Tenant] = %q, want acme", payload.SecretHeaders["X-Tenant"])
	}

	if _, ok := payload.SecretHeaders[""]; ok {
		t.Error("empty header suffix must not produce a SecretHeaders entry")
	}
	if string(payload.Credential) != "tok" {
		t.Errorf("credential = %q, want tok", payload.Credential)
	}
	if payload.ResourceVer != "5/2" {
		t.Errorf("ResourceVer = %q, want 5/2", payload.ResourceVer)
	}
}

func TestLoadBundle_SecretGetNonNotFoundErrorPropagates(t *testing.T) {
	const systemNS = "podtrace-system"
	uid := types.UID("e8c32c91-0000-0000-0000-0000000000bb")
	name := operator.ExporterBundleName(uid)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS, ResourceVersion: "5"},
		Data:       map[string]string{"type": "otlp", "endpoint": "otel:4318"},
	}

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return errors.New("apiserver unavailable")
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()

	_, err := LoadBundle(context.Background(), c, systemNS, uid)
	if err == nil {
		t.Fatal("expected LoadBundle to surface a non-NotFound Secret error")
	}
	if !strings.Contains(err.Error(), "bundle Secret") {
		t.Errorf("error should be wrapped as a Secret load failure, got: %v", err)
	}
}
