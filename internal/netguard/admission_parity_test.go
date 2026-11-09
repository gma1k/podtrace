package netguard_test

import (
	"net"
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/netguard"
)

func TestAdmissionAndTheDialGuardAgreeOnEveryLiteral(t *testing.T) {
	t.Setenv("PODTRACE_EXPORTER_BLOCK_PRIVATE", "false")
	for _, ip := range []string{
		"169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1",
		"fd00:ec2::254", "100.100.100.200", "168.63.129.16",
		"::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe",
		"10.0.0.1", "8.8.8.8", "2001:db8::1",
	} {
		host := ip
		if net.ParseIP(ip).To4() == nil {
			host = "[" + ip + "]"
		}
		spec := podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "http://" + host + ":4318"},
		}
		admitted := podtracev1alpha1.ValidateExporterConfigVariant(spec) == nil
		dialable := !netguard.IsBlockedIP(net.ParseIP(ip))
		if admitted != dialable {
			t.Errorf("%s: admission admits=%v but the dial guard allows=%v", ip, admitted, dialable)
		}
	}
}

func TestAdmissionRejectsAZoneScopedLiteral(t *testing.T) {
	spec := podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeOTLP,
		OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "http://[fe80::1%25eth0]:4318"},
	}
	if err := podtracev1alpha1.ValidateExporterConfigVariant(spec); err == nil {
		t.Fatal("a zone-scoped literal is refused at dial time, so admission must refuse it too")
	}
}
