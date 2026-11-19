package main

import "testing"

const (
	customCertificateStore  = "tracer-webhook-certs"
	defaultCertificateStore = "podtrace-webhook-certs"
)

func TestToOperatorOptions_ManagedWebhookCertificates(t *testing.T) {
	cmd := newOperatorCmd()
	for name, value := range map[string]string{
		"webhook-cert-dir":      "/tmp/certs",
		"webhook-manage-certs":  "true",
		"webhook-cert-secret":   customCertificateStore,
		"webhook-service":       "tracer-webhook",
		"webhook-configuration": "tracer-validating-webhook",
	} {
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatalf("set --%s: %v", name, err)
		}
	}
	opts := &operatorOptions{}
	opts.webhookManageCerts, _ = cmd.Flags().GetBool("webhook-manage-certs")
	opts.webhookSecretName = cmd.Flag("webhook-cert-secret").Value.String()
	opts.webhookServiceName = cmd.Flag("webhook-service").Value.String()
	opts.webhookConfigName = cmd.Flag("webhook-configuration").Value.String()
	opts.webhookCertDir = cmd.Flag("webhook-cert-dir").Value.String()

	got := toOperatorOptions(opts, false).WebhookCertificates
	if got == nil {
		t.Fatal("--webhook-manage-certs did not reach the operator options")
	}
	if got.SecretName != customCertificateStore || got.ServiceName != "tracer-webhook" || got.WebhookConfigurationName != "tracer-validating-webhook" {
		t.Errorf("WebhookCertificates = %+v", got)
	}
}

func TestToOperatorOptions_CertificatesComeFromOutsideByDefault(t *testing.T) {
	cmd := newOperatorCmd()
	manage, _ := cmd.Flags().GetBool("webhook-manage-certs")
	if manage {
		t.Fatal("--webhook-manage-certs must default to false so cert-manager and manual installs keep their certificate")
	}
	if got := toOperatorOptions(&operatorOptions{webhookCertDir: "/tmp/certs"}, false).WebhookCertificates; got != nil {
		t.Fatalf("WebhookCertificates = %+v without --webhook-manage-certs", got)
	}
	for flag, want := range map[string]string{
		"webhook-cert-secret":   defaultCertificateStore,
		"webhook-service":       "podtrace-webhook",
		"webhook-configuration": "podtrace-validating-webhook",
	} {
		if got := cmd.Flag(flag).DefValue; got != want {
			t.Errorf("--%s default = %q, want %q", flag, got, want)
		}
	}
}
