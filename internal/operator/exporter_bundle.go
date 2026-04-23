package operator

import (
	"fmt"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// renderBundlePayload converts an ExporterConfig's typed spec into the
// ConfigMap data and (optionally) a credential-Secret reference that
// the operator will copy into systemNS as part of the bundle.
//
// Bundle schema (ConfigMap.data):
//
//	type                 = otlp | jaeger | zipkin | splunk | datadog
//	endpoint             = full URL or host:port (exporter-specific)
//	protocol             = http | grpc (OTLP only)
//	insecure             = "true" | "false" (OTLP only)
//	site                 = datadoghq.com | datadoghq.eu (DataDog only)
//	sample_percent       = decimal string (optional)
//	headers.<name>       = literal value (OTLP only)
//	header_secret_keys   = space-separated list of ConfigMap keys that
//	                       reference the companion Secret (OTLP only)
//
// The second return value, if non-nil, names the user-namespace Secret
// key the operator should load for the bundle's companion credential
// Secret. Exporters without credentials (Jaeger, Zipkin, credential-less
// OTLP) return nil here.
func renderBundlePayload(ec *podtracev1alpha1.ExporterConfig) (map[string]string, *podtracev1alpha1.SecretKeySelector, error) {
	data := map[string]string{
		"type": string(ec.Spec.Type),
	}
	if ec.Spec.SamplePercent != nil {
		data["sample_percent"] = itoa(int(*ec.Spec.SamplePercent))
	}

	switch ec.Spec.Type {
	case podtracev1alpha1.ExporterTypeOTLP:
		if ec.Spec.OTLP == nil {
			return nil, nil, fmt.Errorf("spec.otlp is required when type=otlp")
		}
		data["endpoint"] = ec.Spec.OTLP.Endpoint
		if ec.Spec.OTLP.Protocol != "" {
			data["protocol"] = string(ec.Spec.OTLP.Protocol)
		} else {
			data["protocol"] = string(podtracev1alpha1.OTLPProtocolHTTP)
		}
		data["insecure"] = boolString(ec.Spec.OTLP.Insecure)
		for _, h := range ec.Spec.OTLP.Headers {
			// Literal-valued headers go straight into the ConfigMap.
			// Secret-valued headers are deferred to the credential path;
			// this first iteration supports exactly one Secret-valued
			// header (the most common pattern — an Authorization bearer).
			if h.ValueFrom != nil {
				// Use the first Secret-backed header as THE credential,
				// exposed in the companion Secret under key "credential".
				// Multi-Secret support is tracked as a future enhancement.
				sk := h.ValueFrom.DeepCopy()
				data["header_secret_name"] = h.Name
				return data, sk, nil
			}
			data["headers."+h.Name] = h.Value
		}
		return data, nil, nil

	case podtracev1alpha1.ExporterTypeJaeger:
		if ec.Spec.Jaeger == nil {
			return nil, nil, fmt.Errorf("spec.jaeger is required when type=jaeger")
		}
		data["endpoint"] = ec.Spec.Jaeger.Endpoint
		return data, nil, nil

	case podtracev1alpha1.ExporterTypeZipkin:
		if ec.Spec.Zipkin == nil {
			return nil, nil, fmt.Errorf("spec.zipkin is required when type=zipkin")
		}
		data["endpoint"] = ec.Spec.Zipkin.Endpoint
		return data, nil, nil

	case podtracev1alpha1.ExporterTypeSplunk:
		if ec.Spec.Splunk == nil {
			return nil, nil, fmt.Errorf("spec.splunk is required when type=splunk")
		}
		data["endpoint"] = ec.Spec.Splunk.Endpoint
		ref := ec.Spec.Splunk.TokenSecretRef
		return data, &ref, nil

	case podtracev1alpha1.ExporterTypeDataDog:
		if ec.Spec.DataDog == nil {
			return nil, nil, fmt.Errorf("spec.datadog is required when type=datadog")
		}
		if ec.Spec.DataDog.Site != "" {
			data["site"] = ec.Spec.DataDog.Site
		} else {
			data["site"] = "datadoghq.com"
		}
		ref := ec.Spec.DataDog.APIKeySecretRef
		return data, &ref, nil

	default:
		return nil, nil, fmt.Errorf("unsupported exporter type %q", ec.Spec.Type)
	}
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
