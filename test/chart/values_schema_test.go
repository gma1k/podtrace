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

func TestValuesSchemaRejectsReservedOrInvalidSystemNamespace(t *testing.T) {
	for _, name := range []string{"Podtrace", "podtrace.system", "-podtrace", strings.Repeat("a", 64)} {
		t.Run(name, func(t *testing.T) {
			if _, err := helmTemplate(t, "--set", "namespace.name="+name); err == nil {
				t.Fatalf("namespace.name=%q rendered; it is not a namespace name", name)
			}
		})
	}
	for _, name := range []string{"default", "kube-system", "kube-public", "kube-node-lease"} {
		t.Run(name, func(t *testing.T) {
			_, err := helmTemplate(t, "--set", "namespace.name="+name)
			if err == nil || !strings.Contains(err.Error(), "one of the cluster's own namespaces") {
				t.Fatalf("namespace.name=%q: err = %v; the namespace-bootstrap hook would label it PSA-privileged before anything refuses it", name, err)
			}
		})
	}
}

func TestValuesSchemaAcceptsSystemNamespace(t *testing.T) {
	for _, name := range []string{"podtrace-system", "observability", "kube-tracing", strings.Repeat("a", 63)} {
		t.Run(name, func(t *testing.T) {
			if _, err := helmTemplate(t, "--set", "namespace.name="+name); err != nil {
				t.Fatalf("namespace.name=%q: %v", name, err)
			}
		})
	}
}

func TestWebhookCertManagerRendersTheIssuerItsCertificateNames(t *testing.T) {
	out := renderChart(t, "webhook.enabled=true")
	if !bytes.Contains(out, []byte("kind: Issuer\nmetadata:\n  name: podtrace-selfsigned\n  namespace: podtrace-system\n")) {
		t.Fatal("no Issuer podtrace-selfsigned rendered in the system namespace; the Certificate names it, so cert-manager would never issue the webhook certificate")
	}
	if !bytes.Contains(out, []byte("spec:\n  selfSigned: {}\n")) {
		t.Error("the rendered Issuer is not selfSigned")
	}

	custom := renderChart(t, "webhook.enabled=true", "webhook.certManager.issuerRef.name=team-ca")
	if !bytes.Contains(custom, []byte("kind: Issuer\nmetadata:\n  name: team-ca\n")) {
		t.Error("a renamed issuerRef must render the Issuer under that name")
	}
}

func TestWebhookCertManagerLeavesIssuerToTheUserWhenAsked(t *testing.T) {
	for name, flags := range map[string][]string{
		"createIssuer=false": {"webhook.enabled=true", "webhook.certManager.createIssuer=false"},
		"ClusterIssuer":      {"webhook.enabled=true", "webhook.certManager.issuerRef.kind=ClusterIssuer", "webhook.certManager.issuerRef.name=corp-ca"},
		"webhook disabled":   {"webhook.enabled=false"},
		"manual certSource":  {"webhook.enabled=true", "webhook.certSource=manual", "webhook.caBundle=Y2E="},
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Contains(renderChart(t, flags...), []byte("\nkind: Issuer\n")) {
				t.Fatalf("an Issuer rendered with %v", flags)
			}
		})
	}
}
