package webhookcert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const certificateStoreName = "podtrace-webhook-certs"

var testStart = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func webhookConfiguration() *admissionregistrationv1.ValidatingWebhookConfiguration {
	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "podtrace-validating-webhook"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{Name: "vpodtrace.podtrace.io"},
			{Name: "vtracerconfig.podtrace.io"},
		},
	}
}

func testClient(t *testing.T, funcs interceptor.Funcs, objects ...client.Object) client.WithWatch {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).WithObjects(objects...).WithInterceptorFuncs(funcs).Build()
}

func newProvisioner(t *testing.T, c client.Client, now *time.Time) *Provisioner {
	t.Helper()
	return &Provisioner{
		Config: Config{
			Namespace:                "podtrace-system",
			SecretName:               certificateStoreName,
			ServiceName:              "podtrace-webhook",
			WebhookConfigurationName: "podtrace-validating-webhook",
			CertDir:                  t.TempDir(),
		},
		Reader: c,
		Writer: c,
		Now:    func() time.Time { return *now },
	}
}

func readSecret(t *testing.T, c client.Client) corev1.Secret {
	t.Helper()
	var s corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "podtrace-system", Name: certificateStoreName}, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func readConfiguration(t *testing.T, c client.Client) admissionregistrationv1.ValidatingWebhookConfiguration {
	t.Helper()
	var v admissionregistrationv1.ValidatingWebhookConfiguration
	if err := c.Get(context.Background(), types.NamespacedName{Name: "podtrace-validating-webhook"}, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func readFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	raw, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func verifyServing(t *testing.T, certPEM, keyPEM, bundle []byte, at time.Time) *x509.Certificate {
	t.Helper()
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("serving pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		t.Fatal("CA bundle holds no certificate")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:     "podtrace-webhook.podtrace-system.svc",
		Roots:       roots,
		CurrentTime: at,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("the API server could not verify the serving certificate: %v", err)
	}
	return leaf
}

func TestEnsure_IssuesCertificateFilesAndCABundle(t *testing.T) {
	now := testStart
	c := testClient(t, interceptor.Funcs{}, webhookConfiguration())
	p := newProvisioner(t, c, &now)

	if err := p.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	secret := readSecret(t, c)
	if secret.Type != corev1.SecretTypeOpaque || secret.Labels[managedByLabel] != managedByValue {
		t.Errorf("Secret type %q labels %v", secret.Type, secret.Labels)
	}
	for _, k := range []string{KeyCACert, KeyCAKey, KeyServingCert, KeyServingKey} {
		if len(secret.Data[k]) == 0 {
			t.Errorf("Secret key %s is empty", k)
		}
	}
	if !bytes.Equal(readFile(t, p.CertDir, KeyServingCert), secret.Data[KeyServingCert]) ||
		!bytes.Equal(readFile(t, p.CertDir, KeyServingKey), secret.Data[KeyServingKey]) {
		t.Error("the files in the certificate directory differ from the Secret")
	}
	for _, w := range readConfiguration(t, c).Webhooks {
		if !bytes.Equal(w.ClientConfig.CABundle, secret.Data[KeyCACert]) {
			t.Errorf("webhook %s caBundle not injected", w.Name)
		}
	}
	leaf := verifyServing(t, secret.Data[KeyServingCert], secret.Data[KeyServingKey], secret.Data[KeyCACert], now)
	for _, name := range p.DNSNames() {
		if !strings.Contains(strings.Join(leaf.DNSNames, ","), name) {
			t.Errorf("serving certificate lacks DNS name %s: %v", name, leaf.DNSNames)
		}
	}
}

func TestEnsure_ValidCertificateIsLeftAlone(t *testing.T) {
	now := testStart
	c := testClient(t, interceptor.Funcs{}, webhookConfiguration())
	p := newProvisioner(t, c, &now)
	if err := p.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	secretVersion := readSecret(t, c).ResourceVersion
	configurationVersion := readConfiguration(t, c).ResourceVersion

	now = now.Add(30 * 24 * time.Hour)
	if err := p.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	if readSecret(t, c).ResourceVersion != secretVersion {
		t.Error("a valid certificate was rewritten")
	}
	if readConfiguration(t, c).ResourceVersion != configurationVersion {
		t.Error("an unchanged caBundle was written again")
	}
}

func TestEnsure_ReplicaAdoptsTheSharedSecret(t *testing.T) {
	now := testStart
	c := testClient(t, interceptor.Funcs{}, webhookConfiguration())
	first := newProvisioner(t, c, &now)
	if err := first.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	version := readSecret(t, c).ResourceVersion

	second := newProvisioner(t, c, &now)
	if err := second.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	if readSecret(t, c).ResourceVersion != version {
		t.Error("the second replica issued its own certificate instead of adopting the shared one")
	}
	if !bytes.Equal(readFile(t, first.CertDir, KeyServingCert), readFile(t, second.CertDir, KeyServingCert)) {
		t.Error("replicas serve different certificates")
	}
}

func TestEnsure_RenewsServingCertificateBeforeExpiry(t *testing.T) {
	now := testStart
	c := testClient(t, interceptor.Funcs{}, webhookConfiguration())
	p := newProvisioner(t, c, &now)
	if err := p.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := readSecret(t, c)

	now = testStart.Add(servingValidity - renewServingBefore + time.Hour)
	if err := p.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	after := readSecret(t, c)
	if bytes.Equal(before.Data[KeyServingCert], after.Data[KeyServingCert]) {
		t.Fatal("a serving certificate with less than a third of its life left was not renewed")
	}
	if !bytes.Equal(before.Data[KeyCACert], after.Data[KeyCACert]) {
		t.Error("renewing the serving certificate changed the CA bundle")
	}
	if !bytes.Equal(readFile(t, p.CertDir, KeyServingCert), after.Data[KeyServingCert]) {
		t.Error("the renewed certificate did not reach the certificate directory")
	}
	verifyServing(t, after.Data[KeyServingCert], after.Data[KeyServingKey], after.Data[KeyCACert], now)
}

func TestEnsure_RotatesCAKeepingTheOldOneUntilItExpires(t *testing.T) {
	now := testStart
	c := testClient(t, interceptor.Funcs{}, webhookConfiguration())
	p := newProvisioner(t, c, &now)
	if err := p.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldCA := decodeCerts(readSecret(t, c).Data[KeyCACert])[0]

	now = testStart.Add(caValidity - renewCABefore + time.Hour)
	if err := p.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	rotated := readSecret(t, c)
	bundle := decodeCerts(rotated.Data[KeyCACert])
	if len(bundle) != 2 || bundle[0].Equal(oldCA) || !bundle[1].Equal(oldCA) {
		t.Fatalf("bundle after rotation holds %d CA(s); want the new CA first and the old one after it", len(bundle))
	}
	leaf := verifyServing(t, rotated.Data[KeyServingCert], rotated.Data[KeyServingKey], rotated.Data[KeyCACert], now)
	if leaf.CheckSignatureFrom(bundle[0]) != nil {
		t.Error("the serving certificate is not signed by the new CA")
	}
	if !bytes.Equal(readConfiguration(t, c).Webhooks[0].ClientConfig.CABundle, rotated.Data[KeyCACert]) {
		t.Error("the rotated bundle did not reach the webhook configuration")
	}

	now = now.Add(24 * time.Hour)
	if err := p.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readSecret(t, c).Data[KeyCACert], rotated.Data[KeyCACert]) {
		t.Fatal("the old CA was dropped from the bundle while it is still valid")
	}

	now = oldCA.NotAfter.Add(time.Hour)
	if err := p.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(decodeCerts(readSecret(t, c).Data[KeyCACert])); n != 1 {
		t.Errorf("bundle holds %d CA(s) after the old CA expired, want 1", n)
	}
}

func TestEnsure_ReissuesWhenTheServiceNameChanges(t *testing.T) {
	now := testStart
	c := testClient(t, interceptor.Funcs{}, webhookConfiguration())
	p := newProvisioner(t, c, &now)
	if err := p.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := readSecret(t, c)

	p.ServiceName = "tracer-webhook"
	if err := p.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	after := readSecret(t, c)
	if bytes.Equal(before.Data[KeyServingCert], after.Data[KeyServingCert]) {
		t.Fatal("a certificate without the new Service's DNS names was kept")
	}
	if !bytes.Equal(before.Data[KeyCACert], after.Data[KeyCACert]) {
		t.Error("a new DNS name must not rotate the CA")
	}
}

func TestEnsure_ReplacesUnusableSecretData(t *testing.T) {
	cases := map[string]map[string][]byte{
		"garbage": {KeyCACert: []byte("junk"), KeyCAKey: []byte("junk"), KeyServingCert: []byte("junk"), KeyServingKey: []byte("junk")},
		"empty":   {},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			now := testStart
			broken := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: certificateStoreName, Namespace: "podtrace-system"},
				Type:       corev1.SecretTypeOpaque,
				Data:       data,
			}
			c := testClient(t, interceptor.Funcs{}, webhookConfiguration(), broken)
			p := newProvisioner(t, c, &now)

			if err := p.Ensure(context.Background()); err != nil {
				t.Fatalf("Ensure: %v", err)
			}
			secret := readSecret(t, c)
			verifyServing(t, secret.Data[KeyServingCert], secret.Data[KeyServingKey], secret.Data[KeyCACert], now)
			if secret.Labels[managedByLabel] != managedByValue {
				t.Errorf("labels = %v, want the operator's", secret.Labels)
			}
		})
	}
}

func TestEnsure_RejectsCAThatDoesNotMatchItsKey(t *testing.T) {
	now := testStart
	c := testClient(t, interceptor.Funcs{}, webhookConfiguration())
	p := newProvisioner(t, c, &now)
	if err := p.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, otherKey, err := newCA(now)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyPEM, err := encodeKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	secret := readSecret(t, c)
	secret.Data[KeyCAKey] = otherKeyPEM
	if err := c.Update(context.Background(), &secret); err != nil {
		t.Fatal(err)
	}

	if err := p.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	reissued := readSecret(t, c)
	ca := decodeCerts(reissued.Data[KeyCACert])[0]
	if !publicKeyMatches(ca, decodeKey(reissued.Data[KeyCAKey])) {
		t.Fatal("the reissued CA does not match its key")
	}
}

func TestEnsure_RefusesToOverwriteForeignSecretType(t *testing.T) {
	now := testStart
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: certificateStoreName, Namespace: "podtrace-system"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{corev1.TLSCertKey: []byte("x"), corev1.TLSPrivateKeyKey: []byte("y")},
	}
	c := testClient(t, interceptor.Funcs{}, webhookConfiguration(), foreign)

	err := newProvisioner(t, c, &now).Ensure(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not Opaque") {
		t.Fatalf("Ensure = %v, want a refusal to overwrite a kubernetes.io/tls Secret", err)
	}
}

func TestEnsure_CreateRaceAdoptsTheWinnersSecret(t *testing.T) {
	now := testStart
	winnerDir := t.TempDir()
	var c client.WithWatch
	raced := false
	c = testClient(t, interceptor.Funcs{
		Create: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*corev1.Secret); ok && !raced {
				raced = true
				winner := &Provisioner{Config: Config{
					Namespace: "podtrace-system", SecretName: certificateStoreName, ServiceName: "podtrace-webhook",
					WebhookConfigurationName: "podtrace-validating-webhook", CertDir: winnerDir,
				}, Reader: inner, Writer: inner, Now: func() time.Time { return now }}
				if err := winner.Ensure(ctx); err != nil {
					t.Fatal(err)
				}
				return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, certificateStoreName)
			}
			return inner.Create(ctx, obj, opts...)
		},
	}, webhookConfiguration())
	p := newProvisioner(t, c, &now)

	if err := p.Ensure(context.Background()); err == nil {
		t.Fatal("a lost create race must be reported so the caller retries")
	}
	if err := p.Ensure(context.Background()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !bytes.Equal(readFile(t, p.CertDir, KeyServingCert), readFile(t, winnerDir, KeyServingCert)) {
		t.Error("the replica that lost the race does not serve the winner's certificate")
	}
}

func TestEnsure_ReportsAPIFailures(t *testing.T) {
	failing := errors.New("api unavailable")
	cases := map[string]struct {
		funcs   interceptor.Funcs
		objects []client.Object
		want    string
	}{
		"secret read": {
			funcs: interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return failing
				}
				return c.Get(ctx, key, obj, opts...)
			}},
			objects: []client.Object{webhookConfiguration()},
			want:    "read webhook certificate Secret",
		},
		"secret update": {
			funcs: interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return failing
				}
				return c.Update(ctx, obj, opts...)
			}},
			objects: []client.Object{webhookConfiguration(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: certificateStoreName, Namespace: "podtrace-system"}}},
			want:    "update webhook certificate Secret",
		},
		"missing webhook configuration": {
			want: "read ValidatingWebhookConfiguration",
		},
		"webhook configuration update": {
			funcs: interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if _, ok := obj.(*admissionregistrationv1.ValidatingWebhookConfiguration); ok {
					return failing
				}
				return c.Update(ctx, obj, opts...)
			}},
			objects: []client.Object{webhookConfiguration()},
			want:    "inject CA into ValidatingWebhookConfiguration",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			now := testStart
			c := testClient(t, tc.funcs, tc.objects...)
			err := newProvisioner(t, c, &now).Ensure(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Ensure = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestEnsure_UnwritableCertificateDirectory(t *testing.T) {
	now := testStart
	c := testClient(t, interceptor.Funcs{}, webhookConfiguration())
	p := newProvisioner(t, c, &now)
	p.CertDir = filepath.Join(t.TempDir(), "missing")

	if err := p.Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "write webhook") {
		t.Fatalf("Ensure = %v, want a write failure", err)
	}
}

func TestConfigValidate_RequiresEveryName(t *testing.T) {
	full := Config{Namespace: "ns", SecretName: "s", ServiceName: "svc", WebhookConfigurationName: "vwc", CertDir: "/tmp"}
	if err := full.Validate(); err != nil {
		t.Fatalf("complete config: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"namespace":                  func(c *Config) { c.Namespace = "" },
		"secret name":                func(c *Config) { c.SecretName = "" },
		"service name":               func(c *Config) { c.ServiceName = "" },
		"webhook configuration name": func(c *Config) { c.WebhookConfigurationName = "" },
		"certificate directory":      func(c *Config) { c.CertDir = "" },
	} {
		cfg := full
		mutate(&cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("empty %s: Validate = %v", name, err)
		}
		if err := (&Provisioner{Config: cfg}).Ensure(context.Background()); err == nil {
			t.Errorf("empty %s: Ensure ran", name)
		}
	}
}

func TestStart_RenewsOnEveryCheckUntilCancelled(t *testing.T) {
	now := testStart
	c := testClient(t, interceptor.Funcs{}, webhookConfiguration())
	p := newProvisioner(t, c, &now)
	p.CheckPeriod = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx) }()

	deadline := time.After(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(p.CertDir, KeyServingCert)); err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the renewal loop never issued a certificate")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Start returned %v after cancel", err)
	}
}

func TestStart_KeepsRunningAfterAFailedCheck(t *testing.T) {
	now := testStart
	c := testClient(t, interceptor.Funcs{})
	p := newProvisioner(t, c, &now)
	p.CheckPeriod = time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start = %v; a failed check must be logged, not end the loop", err)
	}
}

func TestStart_DefaultCheckPeriod(t *testing.T) {
	p := &Provisioner{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if p.NeedLeaderElection() {
		t.Error("standby replicas serve webhook calls too, so every replica must keep its certificate current")
	}
}

func TestProvisionerNowDefaultsToWallClock(t *testing.T) {
	before := time.Now()
	got := (&Provisioner{}).now()
	if got.Before(before) || got.After(time.Now()) {
		t.Errorf("now() = %v, want the wall clock", got)
	}
}

func TestDecodeKeyRejectsOtherBlocks(t *testing.T) {
	if decodeKey([]byte("not pem")) != nil {
		t.Error("garbage decoded as a key")
	}
	certPEM := encodeCertForTest(t)
	if decodeKey(certPEM) != nil {
		t.Error("a CERTIFICATE block decoded as a key")
	}
	if decodeKey([]byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n")) != nil {
		t.Error("a malformed EC key decoded")
	}
}

func TestDecodeCertsSkipsOtherBlocks(t *testing.T) {
	_, key, err := newCA(testStart)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certs := decodeCerts(append(keyPEM, encodeCertForTest(t)...))
	if len(certs) != 1 {
		t.Fatalf("decoded %d certificates, want only the CERTIFICATE block", len(certs))
	}
}

func TestServingUsableRejectsBrokenPairs(t *testing.T) {
	ca, caKey, err := newCA(testStart)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"svc", "svc.ns", "svc.ns.svc", "svc.ns.svc.cluster.local"}
	certPEM, keyPEM, err := newServing(ca, caKey, names, testStart)
	if err != nil {
		t.Fatal(err)
	}
	if !servingUsable(certPEM, keyPEM, ca, names, testStart) {
		t.Fatal("a fresh certificate is not usable")
	}
	otherCA, _, err := newCA(testStart)
	if err != nil {
		t.Fatal(err)
	}
	if servingUsable(certPEM, keyPEM, otherCA, names, testStart) {
		t.Error("a certificate from another CA is usable")
	}
	if servingUsable(certPEM, []byte("junk"), ca, names, testStart) {
		t.Error("a certificate without its key is usable")
	}
}

func TestNewServingNeverOutlivesItsCA(t *testing.T) {
	ca, caKey, err := newCA(testStart)
	if err != nil {
		t.Fatal(err)
	}
	late := ca.NotAfter.Add(-24 * time.Hour)
	certPEM, _, err := newServing(ca, caKey, []string{"a", "b", "c", "d"}, late)
	if err != nil {
		t.Fatal(err)
	}
	leaf := decodeCerts(certPEM)[0]
	if leaf.NotAfter.After(ca.NotAfter) {
		t.Errorf("serving certificate expires %v, after its CA %v", leaf.NotAfter, ca.NotAfter)
	}
}

func encodeCertForTest(t *testing.T) []byte {
	t.Helper()
	ca, _, err := newCA(testStart)
	if err != nil {
		t.Fatal(err)
	}
	return encodeCert(ca)
}

func TestEnsure_RenameFailureIsReported(t *testing.T) {
	now := testStart
	c := testClient(t, interceptor.Funcs{}, webhookConfiguration())
	p := newProvisioner(t, c, &now)
	if err := os.MkdirAll(filepath.Join(p.CertDir, KeyServingCert, "occupied"), 0o750); err != nil {
		t.Fatal(err)
	}

	err := p.Ensure(context.Background())
	if err == nil || !strings.Contains(err.Error(), "install webhook") {
		t.Fatalf("Ensure = %v, want the rename failure", err)
	}
	if _, statErr := os.Stat(filepath.Join(p.CertDir, "."+KeyServingCert+".tmp")); !os.IsNotExist(statErr) {
		t.Error("the temporary file was left behind")
	}
}

func TestEnsure_ReportsCryptoFailures(t *testing.T) {
	boom := errors.New("boom")
	realGenerate, realSign, realParse, realMarshal, realSerial := generateKey, signCertificate, parseCertificate, marshalKey, newSerial
	t.Cleanup(func() {
		generateKey, signCertificate, parseCertificate, marshalKey, newSerial = realGenerate, realSign, realParse, realMarshal, realSerial
	})
	restore := func() {
		generateKey, signCertificate, parseCertificate, marshalKey, newSerial = realGenerate, realSign, realParse, realMarshal, realSerial
	}
	failOnCall := func(n int) func() bool {
		calls := 0
		return func() bool {
			calls++
			return calls == n
		}
	}
	cases := map[string]struct {
		install func()
		want    string
	}{
		"CA key": {func() {
			generateKey = func() (*ecdsa.PrivateKey, error) { return nil, boom }
		}, "generate webhook CA key"},
		"CA serial": {func() {
			newSerial = func() (*big.Int, error) { return nil, boom }
		}, "generate certificate serial"},
		"CA signature": {func() {
			signCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) { return nil, boom }
		}, "sign webhook CA"},
		"CA parse": {func() {
			parseCertificate = func([]byte) (*x509.Certificate, error) { return nil, boom }
		}, "parse webhook CA"},
		"serving key": {func() {
			fail := failOnCall(2)
			generateKey = func() (*ecdsa.PrivateKey, error) {
				if fail() {
					return nil, boom
				}
				return realGenerate()
			}
		}, "generate webhook serving key"},
		"serving serial": {func() {
			fail := failOnCall(2)
			newSerial = func() (*big.Int, error) {
				if fail() {
					return nil, boom
				}
				return realSerial()
			}
		}, "generate certificate serial"},
		"serving signature": {func() {
			fail := failOnCall(2)
			signCertificate = func(r io.Reader, tmpl, parent *x509.Certificate, pub, priv any) ([]byte, error) {
				if fail() {
					return nil, boom
				}
				return realSign(r, tmpl, parent, pub, priv)
			}
		}, "sign webhook serving certificate"},
		"serving key encoding": {func() {
			fail := failOnCall(1)
			marshalKey = func(k *ecdsa.PrivateKey) ([]byte, error) {
				if fail() {
					return nil, boom
				}
				return realMarshal(k)
			}
		}, "encode webhook key"},
		"CA key encoding": {func() {
			fail := failOnCall(2)
			marshalKey = func(k *ecdsa.PrivateKey) ([]byte, error) {
				if fail() {
					return nil, boom
				}
				return realMarshal(k)
			}
		}, "encode webhook key"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			restore()
			tc.install()
			defer restore()
			now := testStart
			c := testClient(t, interceptor.Funcs{}, webhookConfiguration())
			err := newProvisioner(t, c, &now).Ensure(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Ensure = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestEnsure_LinkInCertificateDirectoryIsNeverFollowed(t *testing.T) {
	now := testStart
	c := testClient(t, interceptor.Funcs{}, webhookConfiguration())
	issuer := newProvisioner(t, c, &now)
	if err := issuer.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	issued := readSecret(t, c).Data[KeyServingCert]

	p := newProvisioner(t, c, &now)
	outsideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideDir, "planted"), issued, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outsideDir, "planted"), filepath.Join(p.CertDir, KeyServingCert)); err != nil {
		t.Fatal(err)
	}

	if err := p.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	info, err := os.Lstat(filepath.Join(p.CertDir, KeyServingCert))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("%s is still a link out of the certificate directory (%v); whoever controls its target controls the served certificate", KeyServingCert, info.Mode())
	}
	if !bytes.Equal(readFile(t, p.CertDir, KeyServingCert), issued) {
		t.Error("the certificate directory does not serve the issued certificate")
	}
	if !bytes.Equal(readFile(t, outsideDir, "planted"), issued) {
		t.Error("the file outside the certificate directory was modified")
	}
}

func TestEnsure_TemporaryFileWriteFailureIsReported(t *testing.T) {
	now := testStart
	c := testClient(t, interceptor.Funcs{}, webhookConfiguration())
	p := newProvisioner(t, c, &now)
	for _, name := range []string{KeyServingCert, KeyServingKey} {
		if err := os.Mkdir(filepath.Join(p.CertDir, "."+name+".tmp"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	err := p.Ensure(context.Background())
	if err == nil || !strings.Contains(err.Error(), "write webhook tls.") {
		t.Fatalf("Ensure = %v, want the temporary file write failure", err)
	}
}
