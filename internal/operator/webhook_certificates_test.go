package operator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gma1k/podtrace/internal/webhookcert"
)

type fakeCertificateManager struct {
	client  client.Client
	added   []manager.Runnable
	addFail error
}

func (m *fakeCertificateManager) GetAPIReader() client.Reader { return m.client }
func (m *fakeCertificateManager) GetClient() client.Client    { return m.client }
func (m *fakeCertificateManager) Add(r manager.Runnable) error {
	if m.addFail != nil {
		return m.addFail
	}
	m.added = append(m.added, r)
	return nil
}

func shortCertificateBackoff(t *testing.T) {
	t.Helper()
	previous := webhookCertificateBackoff
	webhookCertificateBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 3}
	t.Cleanup(func() { webhookCertificateBackoff = previous })
}

const certificateStoreName = "podtrace-webhook-certs"

func certificateOptions(t *testing.T) Options {
	t.Helper()
	opts := DefaultOptions()
	opts.WebhookCertDir = t.TempDir()
	opts.WebhookCertificates = &WebhookCertificateOptions{
		SecretName:               certificateStoreName,
		ServiceName:              "podtrace-webhook",
		WebhookConfigurationName: "podtrace-validating-webhook",
	}
	return opts
}

func certificateClient(t *testing.T, funcs interceptor.Funcs, withConfiguration bool) client.Client {
	t.Helper()
	b := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithInterceptorFuncs(funcs)
	if withConfiguration {
		b = b.WithObjects(&admissionregistrationv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "podtrace-validating-webhook"},
			Webhooks:   []admissionregistrationv1.ValidatingWebhook{{Name: "vpodtrace.podtrace.io"}},
		})
	}
	return b.Build()
}

func TestProvisionWebhookCertificates_OffUnlessTheOperatorManagesThem(t *testing.T) {
	mgr := &fakeCertificateManager{}
	opts := DefaultOptions()
	if err := provisionWebhookCertificates(context.Background(), mgr, opts); err != nil {
		t.Fatal(err)
	}
	if len(mgr.added) != 0 {
		t.Fatal("a renewal loop was registered although cert-manager or the user provides the certificate")
	}
}

func TestProvisionWebhookCertificates_IssuesBeforeStartAndRegistersRenewal(t *testing.T) {
	opts := certificateOptions(t)
	mgr := &fakeCertificateManager{client: certificateClient(t, interceptor.Funcs{}, true)}

	if err := provisionWebhookCertificates(context.Background(), mgr, opts); err != nil {
		t.Fatalf("provision: %v", err)
	}
	for _, name := range []string{webhookcert.KeyServingCert, webhookcert.KeyServingKey} {
		if _, err := os.Stat(filepath.Join(opts.WebhookCertDir, name)); err != nil {
			t.Errorf("%s not written before the webhook server starts: %v", name, err)
		}
	}
	if len(mgr.added) != 1 {
		t.Fatalf("registered %d runnables, want the renewal loop", len(mgr.added))
	}
	if _, ok := mgr.added[0].(*webhookcert.Provisioner); !ok {
		t.Errorf("registered %T, want the certificate provisioner", mgr.added[0])
	}
}

func TestProvisionWebhookCertificates_RetriesUntilTheCertificateIsIssued(t *testing.T) {
	shortCertificateBackoff(t)
	opts := certificateOptions(t)
	failures := 1
	mgr := &fakeCertificateManager{client: certificateClient(t, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*admissionregistrationv1.ValidatingWebhookConfiguration); ok && failures > 0 {
				failures--
				return errors.New("api server restarting")
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}, true)}

	if err := provisionWebhookCertificates(context.Background(), mgr, opts); err != nil {
		t.Fatalf("a transient failure must be retried: %v", err)
	}
}

func TestProvisionWebhookCertificates_GivesUpWithTheLastError(t *testing.T) {
	shortCertificateBackoff(t)
	opts := certificateOptions(t)
	mgr := &fakeCertificateManager{client: certificateClient(t, interceptor.Funcs{}, false)}

	err := provisionWebhookCertificates(context.Background(), mgr, opts)
	if err == nil || !strings.Contains(err.Error(), "read ValidatingWebhookConfiguration") {
		t.Fatalf("provision = %v, want the underlying failure, not a bare timeout", err)
	}
	if len(mgr.added) != 0 {
		t.Error("a renewal loop was registered for a certificate that was never issued")
	}
}

func TestProvisionWebhookCertificates_CancelledContext(t *testing.T) {
	opts := certificateOptions(t)
	mgr := &fakeCertificateManager{client: certificateClient(t, interceptor.Funcs{}, true)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := provisionWebhookCertificates(ctx, mgr, opts); err == nil {
		t.Fatal("a cancelled start must not report success")
	}
}

func TestProvisionWebhookCertificates_RejectsIncompleteOptions(t *testing.T) {
	opts := certificateOptions(t)
	opts.WebhookCertificates.ServiceName = ""
	mgr := &fakeCertificateManager{client: certificateClient(t, interceptor.Funcs{}, true)}

	if err := provisionWebhookCertificates(context.Background(), mgr, opts); err == nil || !strings.Contains(err.Error(), "service name") {
		t.Fatalf("provision = %v, want the missing service name", err)
	}
}

func TestProvisionWebhookCertificates_RegistrationFailure(t *testing.T) {
	opts := certificateOptions(t)
	mgr := &fakeCertificateManager{client: certificateClient(t, interceptor.Funcs{}, true), addFail: errors.New("manager already started")}

	if err := provisionWebhookCertificates(context.Background(), mgr, opts); err == nil || !strings.Contains(err.Error(), "register webhook certificate renewal") {
		t.Fatalf("provision = %v, want the registration failure", err)
	}
}
