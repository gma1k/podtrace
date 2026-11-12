package chart_test

import (
	"bytes"
	"strings"
	"testing"
)

func TestValuesSchemaRejectsMistypedKeys(t *testing.T) {
	for _, flag := range []string{
		"networkpolicy.enabled=true",
		"networkPolicy.enable=true",
		"tracerConfig.redaction.enable=true",
		"tracerConfig.redactions.enabled=true",
		"tracerConfig.capture.header[0]=x-request-id",
		"agent.alerting.webhookUrl=https://hooks.example.com/x",
		"agent.metrics.inspections.enable=false",
		"agent.allowedImageRepo[0]=registry.example.com/podtrace",
		"operator.objectStore.crossNamespaceAmbientCredential=true",
		"webhook.certsource=manual",
		"image.digests=sha256:0",
	} {
		t.Run(flag, func(t *testing.T) {
			_, err := helmTemplate(t, "--set", flag)
			if err == nil {
				t.Fatalf("--set %s rendered; a mistyped key must fail instead of silently keeping the default", flag)
			}
			if !strings.Contains(err.Error(), "additional properties") {
				t.Errorf("--set %s failed for another reason: %v", flag, err)
			}
		})
	}
}

func TestValuesSchemaAcceptsDocumentedKeys(t *testing.T) {
	for _, flag := range []string{
		"networkPolicy.enabled=true",
		"networkPolicy.allowAPIServerProxy=true",
		"tracerConfig.redaction.enabled=true",
		"tracerConfig.redaction.redactDNSNames=true",
		"tracerConfig.capture.headers[0]=x-request-id",
		"agent.allowedImageRepos[0]=registry.example.com/podtrace",
		"agent.continuousProfiling=false",
		"agent.sockOpsRTT=false",
		"agent.metrics.inspections.holdTime=5m",
		"agent.metrics.inspections.thresholds.http.error_rate=0.1",
		"agent.resources.limits.ephemeral-storage=1Gi",
		"global.imageRegistry=registry.example.com",
		"nameOverride=tracer",
		"fullnameOverride=tracer",
	} {
		t.Run(flag, func(t *testing.T) {
			if _, err := helmTemplate(t, "--set", flag); err != nil {
				t.Errorf("--set %s: %v", flag, err)
			}
		})
	}
}

func TestValuesSchemaRejectsInvalidTracerConfigName(t *testing.T) {
	for _, name := range []string{"Default", "fleet_a", "-fleet"} {
		if _, err := helmTemplate(t, "--set", "tracerConfig.name="+name); err == nil {
			t.Errorf("tracerConfig.name=%q rendered; it is not a valid object name", name)
		}
	}
}

func TestWebhookWithoutCertManagerNeedsACABundle(t *testing.T) {
	for _, source := range []string{"manual", "self-signed"} {
		t.Run(source, func(t *testing.T) {
			_, err := helmTemplate(t, "--set", "webhook.enabled=true", "--set", "webhook.certSource="+source)
			if err == nil || !strings.Contains(err.Error(), "needs webhook.caBundle") {
				t.Fatalf("certSource=%s without caBundle: err = %v, want a render failure naming webhook.caBundle", source, err)
			}

			out := renderChart(t, "webhook.enabled=true", "webhook.certSource="+source, "webhook.caBundle=Y2E=")
			if !bytes.Contains(out, []byte("caBundle: Y2E=")) {
				t.Error("the supplied caBundle did not reach the ValidatingWebhookConfiguration")
			}
			if bytes.Contains(out, []byte("kind: Certificate")) {
				t.Error("a Certificate rendered although cert-manager is not the cert source")
			}
		})
	}
}

func TestWebhookCertSourceMustBeKnown(t *testing.T) {
	_, err := helmTemplate(t, "--set", "webhook.enabled=true", "--set", "webhook.certSource=certmanager", "--set", "webhook.caBundle=Y2E=")
	if err == nil {
		t.Fatal("webhook.certSource=certmanager rendered; a typo must not silently drop the cert-manager Certificate")
	}
}

func TestWebhookCABundleMustBeBase64(t *testing.T) {
	_, err := helmTemplate(t, "--set", "webhook.enabled=true", "--set", "webhook.certSource=manual", "--set", "webhook.caBundle=-----BEGIN CERTIFICATE-----")
	if err == nil {
		t.Fatal("a PEM caBundle rendered; the API server needs it base64-encoded")
	}
}
