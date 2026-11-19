// Package webhookcert lets the operator serve its validating webhook without
// cert-manager. It keeps a private CA and a serving certificate in a Secret,
// writes the serving pair to the webhook server's certificate directory, and
// injects the CA into the operator's own ValidatingWebhookConfiguration.
//
// The Secret is the single source of truth, so every replica and every
// restart serves a certificate from the same CA. The serving certificate is
// renewed well before it expires; a renewed CA is published next to the one
// it replaces until that one expires, so the API server never meets a
// certificate it cannot verify.
package webhookcert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Secret data keys. ca.crt holds the current CA first, then older CAs that
// are still valid; ca.key is the current CA's key.
const (
	KeyServingCert = "tls.crt"
	KeyServingKey  = "tls.key"
	KeyCACert      = "ca.crt"
	KeyCAKey       = "ca.key"
)

const (
	caValidity          = 10 * 365 * 24 * time.Hour
	servingValidity     = 365 * 24 * time.Hour
	renewServingBefore  = servingValidity / 3
	renewCABefore       = 2 * servingValidity
	clockSkewAllowance  = time.Hour
	defaultCheckPeriod  = 10 * time.Minute
	managedByLabel      = "app.kubernetes.io/managed-by"
	managedByValue      = "podtrace-operator"
	componentLabel      = "app.kubernetes.io/component"
	componentLabelValue = "webhook-certificate"
)

// The cryptographic steps are variables so tests can make each one fail.
var (
	generateKey = func() (*ecdsa.PrivateKey, error) {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	signCertificate  = x509.CreateCertificate
	parseCertificate = x509.ParseCertificate
	marshalKey       = x509.MarshalECPrivateKey
	newSerial        = func() (*big.Int, error) {
		return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	}
)

// Config names the objects the provisioner manages.
type Config struct {
	Namespace                string
	SecretName               string
	ServiceName              string
	WebhookConfigurationName string
	CertDir                  string
}

// Provisioner keeps the webhook certificate valid. Reader must read the API
// server directly: the operator's cached client strips Secret data.
type Provisioner struct {
	Config
	Reader      client.Reader
	Writer      client.Writer
	Now         func() time.Time
	CheckPeriod time.Duration
}

// Validate reports a Config that cannot work.
func (c Config) Validate() error {
	for name, value := range map[string]string{
		"namespace":                  c.Namespace,
		"secret name":                c.SecretName,
		"service name":               c.ServiceName,
		"webhook configuration name": c.WebhookConfigurationName,
		"certificate directory":      c.CertDir,
	} {
		if value == "" {
			return fmt.Errorf("webhook certificate %s is empty", name)
		}
	}
	return nil
}

// DNSNames are the names the API server may use to reach the webhook
// Service; the serving certificate must carry all of them.
func (c Config) DNSNames() []string {
	return []string{
		c.ServiceName,
		c.ServiceName + "." + c.Namespace,
		c.ServiceName + "." + c.Namespace + ".svc",
		c.ServiceName + "." + c.Namespace + ".svc.cluster.local",
	}
}

func (p *Provisioner) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Ensure makes the Secret, the files in CertDir and the webhook
// configuration's caBundle agree on a valid certificate.
func (p *Provisioner) Ensure(ctx context.Context) error {
	if err := p.Validate(); err != nil {
		return err
	}
	var secret corev1.Secret
	key := types.NamespacedName{Namespace: p.Namespace, Name: p.SecretName}
	exists := true
	if err := p.Reader.Get(ctx, key, &secret); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("read webhook certificate Secret %s: %w", key, err)
		}
		exists = false
	}

	data, changed, err := p.desired(secret.Data)
	if err != nil {
		return err
	}
	if changed {
		if err := p.store(ctx, &secret, exists, data); err != nil {
			return err
		}
		log.FromContext(ctx).Info("issued webhook serving certificate", "secret", key.String())
	}
	if err := p.writeFiles(data); err != nil {
		return err
	}
	return p.injectCABundle(ctx, data[KeyCACert])
}

// Start re-runs Ensure every CheckPeriod until ctx ends. It runs on every
// replica: each one serves from its own certificate directory.
func (p *Provisioner) Start(ctx context.Context) error {
	period := p.CheckPeriod
	if period <= 0 {
		period = defaultCheckPeriod
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := p.Ensure(ctx); err != nil {
				log.FromContext(ctx).Error(err, "renew webhook certificate")
			}
		}
	}
}

// NeedLeaderElection is false: a standby replica also serves webhook calls.
func (p *Provisioner) NeedLeaderElection() bool { return false }

// desired returns the Secret data to serve, and whether it differs from the
// current data.
func (p *Provisioner) desired(current map[string][]byte) (map[string][]byte, bool, error) {
	now := p.now()
	caCert, caKey, olderCAs := parseCA(current, now)
	caRenewed := false
	if caCert == nil || caCert.NotAfter.Sub(now) < renewCABefore {
		if caCert != nil && caCert.NotAfter.After(now) {
			olderCAs = append([]*x509.Certificate{caCert}, olderCAs...)
		}
		var err error
		caCert, caKey, err = newCA(now)
		if err != nil {
			return nil, false, err
		}
		caRenewed = true
	}

	servingCert, servingKey := current[KeyServingCert], current[KeyServingKey]
	if caRenewed || !servingUsable(servingCert, servingKey, caCert, p.DNSNames(), now) {
		var err error
		servingCert, servingKey, err = newServing(caCert, caKey, p.DNSNames(), now)
		if err != nil {
			return nil, false, err
		}
	}

	caKeyPEM, err := encodeKey(caKey)
	if err != nil {
		return nil, false, err
	}
	bundle := encodeCert(caCert)
	for _, older := range olderCAs {
		bundle = append(bundle, encodeCert(older)...)
	}
	data := map[string][]byte{
		KeyCACert:      bundle,
		KeyCAKey:       caKeyPEM,
		KeyServingCert: servingCert,
		KeyServingKey:  servingKey,
	}
	changed := false
	for k, v := range data {
		if !bytes.Equal(current[k], v) {
			changed = true
		}
	}
	return data, changed, nil
}

// parseCA returns the current CA and its key, and the older CAs in the
// bundle that are still valid. A missing or unusable CA returns nil.
func parseCA(data map[string][]byte, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate) {
	certs := decodeCerts(data[KeyCACert])
	if len(certs) == 0 {
		return nil, nil, nil
	}
	var older []*x509.Certificate
	for _, c := range certs[1:] {
		if c.IsCA && c.NotAfter.After(now) {
			older = append(older, c)
		}
	}
	current := certs[0]
	key := decodeKey(data[KeyCAKey])
	if !current.IsCA || key == nil || !current.NotAfter.After(now) || !publicKeyMatches(current, key) {
		return nil, nil, older
	}
	return current, key, older
}

func servingUsable(certPEM, keyPEM []byte, ca *x509.Certificate, dnsNames []string, now time.Time) bool {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || pair.Leaf == nil {
		return false
	}
	leaf := pair.Leaf
	if leaf.NotAfter.Sub(now) < renewServingBefore || leaf.CheckSignatureFrom(ca) != nil {
		return false
	}
	for _, name := range dnsNames {
		if !slices.Contains(leaf.DNSNames, name) {
			return false
		}
	}
	return true
}

func newCA(now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := generateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generate webhook CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "podtrace-webhook-ca"},
		NotBefore:             now.Add(-clockSkewAllowance),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := signCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign webhook CA: %w", err)
	}
	cert, err := parseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse webhook CA: %w", err)
	}
	return cert, key, nil
}

func newServing(ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsNames []string, now time.Time) ([]byte, []byte, error) {
	key, err := generateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generate webhook serving key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	notAfter := now.Add(servingValidity)
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[2]},
		DNSNames:     dnsNames,
		NotBefore:    now.Add(-clockSkewAllowance),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := signCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign webhook serving certificate: %w", err)
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, nil
}

func encodeCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := marshalKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode webhook key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func decodeCerts(raw []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, cert)
		}
	}
}

func decodeKey(raw []byte) *ecdsa.PrivateKey {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil
	}
	return key
}

func publicKeyMatches(cert *x509.Certificate, key *ecdsa.PrivateKey) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && pub.Equal(&key.PublicKey)
}

func (p *Provisioner) store(ctx context.Context, secret *corev1.Secret, exists bool, data map[string][]byte) error {
	if !exists {
		fresh := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      p.SecretName,
				Namespace: p.Namespace,
				Labels:    map[string]string{managedByLabel: managedByValue, componentLabel: componentLabelValue},
			},
			Type: corev1.SecretTypeOpaque,
			Data: data,
		}
		if err := p.Writer.Create(ctx, fresh); err != nil {
			return fmt.Errorf("create webhook certificate Secret %s/%s: %w", p.Namespace, p.SecretName, err)
		}
		return nil
	}
	if secret.Type != "" && secret.Type != corev1.SecretTypeOpaque {
		return fmt.Errorf("webhook certificate Secret %s/%s has type %s, not Opaque; delete it so the operator can issue its own", p.Namespace, p.SecretName, secret.Type)
	}
	updated := secret.DeepCopy()
	updated.Data = data
	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	updated.Labels[managedByLabel] = managedByValue
	updated.Labels[componentLabel] = componentLabelValue
	if err := p.Writer.Update(ctx, updated); err != nil {
		return fmt.Errorf("update webhook certificate Secret %s/%s: %w", p.Namespace, p.SecretName, err)
	}
	return nil
}

// writeFiles puts the serving pair where the webhook server reads it. Each
// file is replaced by a rename, so the server never reads a partial file.
// Every access goes through an os.Root on CertDir, so a link planted in the
// directory cannot make the operator read or replace a file outside it.
func (p *Provisioner) writeFiles(data map[string][]byte) (err error) {
	root, err := os.OpenRoot(p.CertDir)
	if err != nil {
		return fmt.Errorf("write webhook certificates to %s: %w", p.CertDir, err)
	}
	defer func() { err = errors.Join(err, root.Close()) }()

	for name, content := range map[string][]byte{
		KeyServingCert: data[KeyServingCert],
		KeyServingKey:  data[KeyServingKey],
	} {
		if current, err := root.ReadFile(name); err == nil && bytes.Equal(current, content) {
			continue
		}
		tmp := "." + name + ".tmp"
		if err := root.WriteFile(tmp, content, 0o600); err != nil {
			return fmt.Errorf("write webhook %s: %w", name, err)
		}
		if err := root.Rename(tmp, name); err != nil {
			return errors.Join(fmt.Errorf("install webhook %s: %w", name, err), root.Remove(tmp))
		}
	}
	return nil
}

// injectCABundle sets the CA bundle on every webhook of the operator's own
// configuration, writing only when one differs.
func (p *Provisioner) injectCABundle(ctx context.Context, bundle []byte) error {
	var config admissionregistrationv1.ValidatingWebhookConfiguration
	if err := p.Reader.Get(ctx, types.NamespacedName{Name: p.WebhookConfigurationName}, &config); err != nil {
		return fmt.Errorf("read ValidatingWebhookConfiguration %s: %w", p.WebhookConfigurationName, err)
	}
	changed := false
	for i := range config.Webhooks {
		if !bytes.Equal(config.Webhooks[i].ClientConfig.CABundle, bundle) {
			config.Webhooks[i].ClientConfig.CABundle = bundle
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := p.Writer.Update(ctx, &config); err != nil {
		return fmt.Errorf("inject CA into ValidatingWebhookConfiguration %s: %w", p.WebhookConfigurationName, err)
	}
	return nil
}
