package agent

import (
	"context"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/podtrace/podtrace/internal/operator"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// BundlePayload is the agent-side view of an exporter bundle as
// reconciled by the operator into podtrace-system. It mirrors the
// ConfigMap keys documented in internal/operator/exporter_bundle.go;
// kept as a simple struct so tests can construct one without a client.
type BundlePayload struct {
	Type        string // otlp | jaeger | zipkin | splunk | datadog
	Endpoint    string
	Protocol    string            // otlp: http | grpc
	Insecure    bool              // otlp
	Site        string            // datadog
	Sample      float64           // 0.0 - 1.0
	Headers     map[string]string // otlp literal headers
	HeaderName  string            // otlp secret-backed header name (maps to Credential)
	Credential  []byte            // secret material referenced by the bundle (opaque)
	ResourceVer string            // ConfigMap ResourceVersion for dedup
}

// LoadBundle reads the ConfigMap+optional-Secret pair the operator
// maintains in systemNamespace for the given PodTrace UID, and returns
// the parsed payload. Returns a NotFound error when the ConfigMap is
// missing so the caller can distinguish "not yet synced" from real
// failures.
func LoadBundle(ctx context.Context, c client.Client, systemNamespace string, podtraceUID types.UID) (*BundlePayload, error) {
	name := operator.ExporterBundleName(podtraceUID)

	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: systemNamespace}, &cm); err != nil {
		return nil, fmt.Errorf("get bundle ConfigMap: %w", err)
	}

	payload := &BundlePayload{
		Type:        cm.Data["type"],
		Endpoint:    cm.Data["endpoint"],
		Protocol:    cm.Data["protocol"],
		Site:        cm.Data["site"],
		HeaderName:  cm.Data["header_secret_name"],
		ResourceVer: cm.ResourceVersion,
	}
	if v := cm.Data["insecure"]; v != "" {
		payload.Insecure = v == "true"
	}
	if v := cm.Data["sample_percent"]; v != "" {
		// percent → 0-1 float for the existing OTel samplers.
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 100 {
			payload.Sample = float64(n) / 100.0
		}
	}
	for k, v := range cm.Data {
		const prefix = "headers."
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			if payload.Headers == nil {
				payload.Headers = map[string]string{}
			}
			payload.Headers[k[len(prefix):]] = v
		}
	}

	// Credential Secret is only present when the exporter needed one
	// (Splunk HEC token, DataDog API key, or an OTLP Secret-backed
	// header). NotFound is non-fatal and returns a credential-less
	// payload — valid for credential-less exporters like Jaeger/Zipkin.
	var sec corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: systemNamespace}, &sec); err == nil {
		payload.Credential = sec.Data["credential"]
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get bundle Secret: %w", err)
	}

	return payload, nil
}

// BuildExporter turns a BundlePayload into a tracer.Exporter that
// accepts []*events.Event. For Phase 3 this builds a minimal OTLP
// event exporter; other bundle types return an explicit
// "not-yet-supported" error so the caller surfaces a clean Degraded
// condition instead of silently dropping traces.
//
// Future phases will add Jaeger/Zipkin/Splunk/DataDog adapters; the
// sole caller (the agent's reconcile loop) converts the error into a
// per-CR NodeStatus.Message so the user sees it on kubectl describe.
func BuildExporter(payload *BundlePayload, crKey CRKey) (tracer.Exporter, error) {
	if payload == nil {
		return nil, fmt.Errorf("nil bundle payload")
	}
	switch payload.Type {
	case "otlp":
		return newOTLPEventExporter(crKey, payload)
	case "jaeger", "zipkin", "splunk", "datadog":
		return nil, fmt.Errorf("exporter type %q not yet implemented in agent mode", payload.Type)
	default:
		return nil, fmt.Errorf("unknown exporter type %q", payload.Type)
	}
}
