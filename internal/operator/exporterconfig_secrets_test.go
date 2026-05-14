package operator

import (
	"testing"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestCollectSecretRefs(t *testing.T) {
	tests := []struct {
		name string
		spec podtracev1alpha1.ExporterConfigSpec
		want []secretRef
	}{
		{
			name: "jaeger has no secret refs",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type:   podtracev1alpha1.ExporterTypeJaeger,
				Jaeger: &podtracev1alpha1.JaegerExporter{Endpoint: "http://j:14268"},
			},
			want: nil,
		},
		{
			name: "zipkin has no secret refs",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type:   podtracev1alpha1.ExporterTypeZipkin,
				Zipkin: &podtracev1alpha1.ZipkinExporter{Endpoint: "http://z:9411"},
			},
			want: nil,
		},
		{
			name: "otlp with no header refs",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeOTLP,
				OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4317"},
			},
			want: nil,
		},
		{
			name: "otlp with HeadersFromSecret",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeOTLP,
				OTLP: &podtracev1alpha1.OTLPExporter{
					Endpoint:          "otel:4317",
					HeadersFromSecret: &podtracev1alpha1.LocalObjectReference{Name: "otel-headers"},
				},
			},
			want: []secretRef{{Name: "otel-headers", Required: true}},
		},
		{
			name: "otlp with per-header ValueFrom",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeOTLP,
				OTLP: &podtracev1alpha1.OTLPExporter{
					Endpoint: "otel:4317",
					Headers: []podtracev1alpha1.OTLPHeader{
						{Name: "X-Static", Value: "abc"},
						{Name: "X-Secret", ValueFrom: &podtracev1alpha1.SecretKeySelector{Name: "auth", Key: "token"}},
					},
				},
			},
			want: []secretRef{{Name: "auth", Key: "token", Required: true}},
		},
		{
			name: "splunk requires token secret ref",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeSplunk,
				Splunk: &podtracev1alpha1.SplunkExporter{
					Endpoint:       "https://splunk:8088",
					TokenSecretRef: podtracev1alpha1.SecretKeySelector{Name: "splunk-hec", Key: "token"},
				},
			},
			want: []secretRef{{Name: "splunk-hec", Key: "token", Required: true}},
		},
		{
			name: "datadog requires api key secret ref",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeDataDog,
				DataDog: &podtracev1alpha1.DataDogExporter{
					APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "dd", Key: "api-key"},
				},
			},
			want: []secretRef{{Name: "dd", Key: "api-key", Required: true}},
		},
		{
			name: "otlp with empty HeadersFromSecret name is skipped",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeOTLP,
				OTLP: &podtracev1alpha1.OTLPExporter{
					Endpoint:          "otel:4317",
					HeadersFromSecret: &podtracev1alpha1.LocalObjectReference{Name: ""},
				},
			},
			want: nil,
		},
		{
			name: "otlp with malformed ValueFrom (missing key) is skipped",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeOTLP,
				OTLP: &podtracev1alpha1.OTLPExporter{
					Endpoint: "otel:4317",
					Headers: []podtracev1alpha1.OTLPHeader{
						{Name: "X-Bad", ValueFrom: &podtracev1alpha1.SecretKeySelector{Name: "x", Key: ""}},
					},
				},
			},
			want: nil,
		},
		{
			name: "otlp with both HeadersFromSecret and per-header refs",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeOTLP,
				OTLP: &podtracev1alpha1.OTLPExporter{
					Endpoint:          "otel:4317",
					HeadersFromSecret: &podtracev1alpha1.LocalObjectReference{Name: "bulk"},
					Headers: []podtracev1alpha1.OTLPHeader{
						{Name: "X-A", ValueFrom: &podtracev1alpha1.SecretKeySelector{Name: "a", Key: "k"}},
					},
				},
			},
			want: []secretRef{
				{Name: "bulk", Required: true},
				{Name: "a", Key: "k", Required: true},
			},
		},
		{
			name: "nil typed fields do not panic",
			spec: podtracev1alpha1.ExporterConfigSpec{Type: podtracev1alpha1.ExporterTypeOTLP},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := collectSecretRefs(tc.spec)
			if !secretRefsEqual(got, tc.want) {
				t.Fatalf("collectSecretRefs:\n  got:  %+v\n  want: %+v", got, tc.want)
			}
		})
	}
}

func secretRefsEqual(a, b []secretRef) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
