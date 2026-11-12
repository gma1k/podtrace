package objectstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gma1k/podtrace/internal/netguard"
)

func serviceAccountJSONWithTokenURI(t *testing.T, tokenURI string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	raw, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"project_id":   "podtrace-test",
		"private_key":  string(keyPEM),
		"client_email": "reporter@podtrace-test.iam.gserviceaccount.com",
		"token_uri":    tokenURI,
	})
	if err != nil {
		t.Fatalf("marshal service account JSON: %v", err)
	}
	return raw
}

func uploadWithServiceAccount(t *testing.T, saJSON []byte, endpoint string) error {
	t.Helper()
	sink, err := New(context.Background(), Config{
		URI: "gs://bucket/reports/",
		Credentials: map[string][]byte{
			gcsSecretKeyServiceAccountJSON: saJSON,
			gcsSecretKeyEndpoint:           []byte(endpoint),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = sink.Close() }()
	_, err = sink.Upload(context.Background(), "report.txt", "text/plain", bytes.NewReader([]byte("report")))
	return err
}

func TestGCSTokenRequestRefusesRedirect(t *testing.T) {
	var redirectTargetHits atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectTargetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	var tokenHits atomic.Int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHits.Add(1)
		http.Redirect(w, r, redirectTarget.URL+"/stolen", http.StatusTemporaryRedirect)
	}))
	defer tokenServer.Close()

	var bucketHits atomic.Int32
	bucket := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		bucketHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer bucket.Close()

	err := uploadWithServiceAccount(t, serviceAccountJSONWithTokenURI(t, tokenServer.URL+"/token"), bucket.URL)
	if err == nil {
		t.Fatal("upload succeeded although the token endpoint only redirects")
	}
	if tokenHits.Load() == 0 {
		t.Fatal("token endpoint was never asked for a token")
	}
	if got := redirectTargetHits.Load(); got != 0 {
		t.Fatalf("token request followed the redirect %d time(s)", got)
	}
	if got := bucketHits.Load(); got != 0 {
		t.Fatalf("bucket received %d request(s) without a token", got)
	}
	if !strings.Contains(err.Error(), "refusing redirect") {
		t.Fatalf("error does not name the refused redirect: %v", err)
	}
}

func TestGCSTokenRequestRefusesLinkLocalTokenURI(t *testing.T) {
	bucket := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer bucket.Close()

	err := uploadWithServiceAccount(t, serviceAccountJSONWithTokenURI(t, "http://169.254.169.254/computeMetadata/v1/token"), bucket.URL)
	if err == nil {
		t.Fatal("upload succeeded with a link-local token_uri")
	}
	if !errors.Is(err, netguard.ErrBlocked) && !strings.Contains(err.Error(), netguard.ErrBlocked.Error()) {
		t.Fatalf("token request was not refused by the egress guard: %v", err)
	}
}
