package operator

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStripSecretData_RemovesPlaintextKeepsMetadata(t *testing.T) {
	in := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:          "creds",
			Namespace:     "team-a",
			Labels:        map[string]string{"app": "billing"},
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}},
		},
		Data:       map[string][]byte{"token": []byte("s3cr3t")},
		StringData: map[string]string{"token": "s3cr3t"},
		Type:       corev1.SecretTypeOpaque,
	}

	out, err := stripSecretData(in)
	if err != nil {
		t.Fatalf("stripSecretData error: %v", err)
	}
	s, ok := out.(*corev1.Secret)
	if !ok {
		t.Fatalf("stripSecretData returned %T, want *corev1.Secret", out)
	}
	if s.Data != nil {
		t.Errorf("Data must be cleared, got %v", s.Data)
	}
	if s.StringData != nil {
		t.Errorf("StringData must be cleared, got %v", s.StringData)
	}
	if s.ManagedFields != nil {
		t.Error("ManagedFields must be cleared")
	}
	if s.Name != "creds" || s.Namespace != "team-a" || s.Labels["app"] != "billing" {
		t.Error("metadata (name/namespace/labels) must be preserved for watches and label-scoped lists")
	}
	if s.Type != corev1.SecretTypeOpaque {
		t.Error("Type must be preserved")
	}
}

func TestStripSecretData_PassesThroughNonSecret(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm"}}
	out, err := stripSecretData(cm)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if out != any(cm) {
		t.Error("non-Secret object must pass through unchanged")
	}
}
