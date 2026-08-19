package objectstore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func TestNewGCSSink_RejectsExternalAccountJSON(t *testing.T) {
	externalAccount := `{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_url": "https://sts.attacker.example/v1/token",
  "credential_source": {"url": "https://attacker.example/token"}
}`

	_, err := New(context.Background(), Config{
		URI: "gs://bucket/reports/",
		Credentials: map[string][]byte{
			gcsSecretKeyServiceAccountJSON: []byte(externalAccount),
		},
	})
	if err == nil {
		t.Fatal("expected external_account credential JSON to be rejected")
	}
	if !strings.Contains(err.Error(), "service account JSON") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewGCSSink_AcceptsServiceAccountJSON(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	saJSON, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"project_id":   "podtrace-test",
		"private_key":  string(keyPEM),
		"client_email": "reporter@podtrace-test.iam.gserviceaccount.com",
		"token_uri":    "https://oauth2.googleapis.com/token",
	})
	if err != nil {
		t.Fatalf("marshal service account JSON: %v", err)
	}

	sink, err := New(context.Background(), Config{
		URI: "gs://bucket/reports/",
		Credentials: map[string][]byte{
			gcsSecretKeyServiceAccountJSON: saJSON,
		},
	})
	if err != nil {
		t.Fatalf("New (service account JSON): %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
}
