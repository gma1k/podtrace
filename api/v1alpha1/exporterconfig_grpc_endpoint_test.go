package v1alpha1

import (
	"strings"
	"testing"
)

func grpcSpec(protocol OTLPProtocol, endpoint string) ExporterConfigSpec {
	return ExporterConfigSpec{
		Type: ExporterTypeOTLP,
		OTLP: &OTLPExporter{Endpoint: endpoint, Protocol: protocol},
	}
}

func TestAdmissionRefusesAGRPCEndpointWithAURLPath(t *testing.T) {
	for _, endpoint := range []string{
		"https://collector.example:4318/v1/traces",
		"otel.observability:4318/v1/traces",
	} {
		err := ValidateExporterConfigVariant(grpcSpec(OTLPProtocolGRPC, endpoint))
		if err == nil || !strings.Contains(err.Error(), "protocol grpc takes host:port") {
			t.Errorf("%s: err = %v, want the URL path refusal", endpoint, err)
		}
	}
}

func TestAdmissionAcceptsGRPCHostPortEndpoints(t *testing.T) {
	for _, endpoint := range []string{
		"otel.observability:4317",
		"http://otel.observability:4317",
		"https://collector.example:4317/",
	} {
		if err := ValidateExporterConfigVariant(grpcSpec(OTLPProtocolGRPC, endpoint)); err != nil {
			t.Errorf("%s: %v", endpoint, err)
		}
	}
}

func TestAdmissionKeepsHTTPPathsForTheHTTPProtocol(t *testing.T) {
	for _, protocol := range []OTLPProtocol{"", OTLPProtocolHTTP} {
		if err := ValidateExporterConfigVariant(grpcSpec(protocol, "https://collector.example:4318/v1/traces")); err != nil {
			t.Errorf("protocol %q: %v", protocol, err)
		}
	}
}

func TestValidateGRPCEndpointReportsAnUnparseableURL(t *testing.T) {
	if err := validateGRPCEndpoint("https://collector.example:bad port"); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("err = %v, want the parse error", err)
	}
}
