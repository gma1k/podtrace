package operator

import (
	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// secretRef is one (Secret-name, required-key) pair an ExporterConfig
// depends on.
type secretRef struct {
	Name     string
	Key      string
	Required bool
}

// collectSecretRefs returns every Secret reference an ExporterConfig
// declares, regardless of its Type.
func collectSecretRefs(spec podtracev1alpha1.ExporterConfigSpec) []secretRef {
	var out []secretRef

	if spec.OTLP != nil {
		if spec.OTLP.HeadersFromSecret != nil && spec.OTLP.HeadersFromSecret.Name != "" {
			out = append(out, secretRef{
				Name:     spec.OTLP.HeadersFromSecret.Name,
				Required: true,
			})
		}
		for _, h := range spec.OTLP.Headers {
			if h.ValueFrom == nil {
				continue
			}
			if h.ValueFrom.Name == "" || h.ValueFrom.Key == "" {
				continue
			}
			out = append(out, secretRef{
				Name:     h.ValueFrom.Name,
				Key:      h.ValueFrom.Key,
				Required: true,
			})
		}
	}

	if spec.Splunk != nil && spec.Splunk.TokenSecretRef.Name != "" {
		out = append(out, secretRef{
			Name:     spec.Splunk.TokenSecretRef.Name,
			Key:      spec.Splunk.TokenSecretRef.Key,
			Required: true,
		})
	}

	if spec.DataDog != nil && spec.DataDog.APIKeySecretRef.Name != "" {
		out = append(out, secretRef{
			Name:     spec.DataDog.APIKeySecretRef.Name,
			Key:      spec.DataDog.APIKeySecretRef.Key,
			Required: true,
		})
	}

	return out
}
