package operator

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gma1k/podtrace/internal/webhookcert"
)

// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;update

// WebhookCertificateOptions names the objects the operator keeps the
// webhook certificate in.
type WebhookCertificateOptions struct {
	SecretName               string
	ServiceName              string
	WebhookConfigurationName string
}

// webhookCertificateBackoff bounds the startup wait for the first
// certificate: long enough to ride out an API server hiccup or a replica
// writing the Secret at the same moment, short enough that a missing RBAC
// grant fails the pod visibly instead of hanging.
var webhookCertificateBackoff = wait.Backoff{Duration: 500 * time.Millisecond, Factor: 2, Steps: 8, Cap: 30 * time.Second}

// certificateManager is the part of manager.Manager the provisioner needs.
type certificateManager interface {
	GetAPIReader() client.Reader
	GetClient() client.Client
	Add(manager.Runnable) error
}

// provisionWebhookCertificates issues the webhook certificate before the
// manager starts, because the webhook server reads its files on start, and
// registers the renewal loop. It does nothing unless the operator manages
// the certificate.
func provisionWebhookCertificates(ctx context.Context, mgr certificateManager, opts Options) error {
	certs := opts.WebhookCertificates
	if certs == nil {
		return nil
	}
	provisioner := &webhookcert.Provisioner{
		Config: webhookcert.Config{
			Namespace:                opts.SystemNamespace,
			SecretName:               certs.SecretName,
			ServiceName:              certs.ServiceName,
			WebhookConfigurationName: certs.WebhookConfigurationName,
			CertDir:                  opts.WebhookCertDir,
		},
		Reader: mgr.GetAPIReader(),
		Writer: mgr.GetClient(),
	}
	if err := provisioner.Validate(); err != nil {
		return err
	}
	var last error
	err := wait.ExponentialBackoffWithContext(ctx, webhookCertificateBackoff, func(ctx context.Context) (bool, error) {
		last = provisioner.Ensure(ctx)
		if last != nil {
			log.FromContext(ctx).Info("webhook certificate not ready yet; retrying", "error", last.Error())
		}
		return last == nil, nil
	})
	if err != nil {
		if last != nil {
			err = last
		}
		return fmt.Errorf("issue webhook certificate: %w", err)
	}
	if err := mgr.Add(provisioner); err != nil {
		return fmt.Errorf("register webhook certificate renewal: %w", err)
	}
	return nil
}
