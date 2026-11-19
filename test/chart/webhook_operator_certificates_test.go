package chart_test

import (
	"bytes"
	"strings"
	"testing"
)

func TestWebhookOperatorCertificatesRenderNoCertManagerObjects(t *testing.T) {
	out := renderChart(t, "webhook.enabled=true", "webhook.certSource=operator")

	for _, absent := range []string{"\nkind: Certificate\n", "\nkind: Issuer\n", "cert-manager.io/inject-ca-from", "caBundle:"} {
		if bytes.Contains(out, []byte(absent)) {
			t.Errorf("operator-managed certificates rendered %q", strings.TrimSpace(absent))
		}
	}
	for _, flag := range []string{
		"- --webhook-manage-certs=true",
		"- --webhook-cert-secret=podtrace-webhook-certs",
		"- --webhook-service=podtrace-webhook",
		"- --webhook-configuration=podtrace-validating-webhook",
	} {
		if !bytes.Contains(out, []byte(flag)) {
			t.Errorf("operator args lack %s", flag)
		}
	}
	if !bytes.Contains(out, []byte("emptyDir:\n            medium: Memory")) {
		t.Error("the certificate directory is not an in-memory emptyDir the operator can write")
	}
	if !bytes.Contains(out, []byte("mountPath: /tmp/k8s-webhook-server/serving-certs\n              readOnly: false")) {
		t.Error("the certificate directory is mounted read-only, so the operator cannot write its certificate")
	}
}

func TestWebhookOperatorCertificatesIgnoreASuppliedCABundle(t *testing.T) {
	out := renderChart(t, "webhook.enabled=true", "webhook.certSource=operator", "webhook.caBundle=Y2E=")
	if bytes.Contains(out, []byte("caBundle:")) {
		t.Fatal("a caBundle rendered in operator mode; every helm upgrade would overwrite the CA the operator injected")
	}
}

func TestWebhookOperatorCertificatesGrantOnlyItsOwnWebhookConfiguration(t *testing.T) {
	out := string(renderChart(t, "webhook.enabled=true", "webhook.certSource=operator"))
	rule := `  - apiGroups: ["admissionregistration.k8s.io"]
    resources: ["validatingwebhookconfigurations"]
    resourceNames: ["podtrace-validating-webhook"]
    verbs: ["get", "update"]`
	if !strings.Contains(out, rule) {
		t.Fatal("the operator lacks get/update on exactly its own ValidatingWebhookConfiguration")
	}
	if strings.Count(out, "validatingwebhookconfigurations") != 1 {
		t.Error("validatingwebhookconfigurations is granted more than once")
	}

	renamed := string(renderChart(t, "webhook.enabled=true", "webhook.certSource=operator", "fullnameOverride=tracer"))
	for _, want := range []string{`resourceNames: ["tracer-validating-webhook"]`, "- --webhook-configuration=tracer-validating-webhook", "- --webhook-service=tracer-webhook", "- --webhook-cert-secret=tracer-webhook-certs"} {
		if !strings.Contains(renamed, want) {
			t.Errorf("fullnameOverride=tracer: missing %s", want)
		}
	}
}

func TestWebhookOtherCertSourcesGrantNoWebhookConfigurationAccess(t *testing.T) {
	for name, flags := range map[string][]string{
		"cert-manager":     {"webhook.enabled=true"},
		"manual":           {"webhook.enabled=true", "webhook.certSource=manual", "webhook.caBundle=Y2E="},
		"webhook disabled": {"webhook.certSource=operator"},
	} {
		t.Run(name, func(t *testing.T) {
			out := renderChart(t, flags...)
			if bytes.Contains(out, []byte("validatingwebhookconfigurations")) {
				t.Error("the operator was granted access to webhook configurations it does not manage")
			}
			if bytes.Contains(out, []byte("--webhook-manage-certs")) {
				t.Error("the operator was told to manage a certificate someone else provides")
			}
		})
	}
}

func TestWebhookCertSourceOperatorIsAccepted(t *testing.T) {
	if _, err := helmTemplate(t, "--set", "webhook.enabled=true", "--set", "webhook.certSource=operator"); err != nil {
		t.Fatalf("certSource=operator without caBundle: %v", err)
	}
}
