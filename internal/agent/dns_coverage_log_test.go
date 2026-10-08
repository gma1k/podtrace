package agent

import (
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
)

func TestTheAgentSaysWhichLookupsItCannotSeeWithoutPacketCapture(t *testing.T) {
	var lines []string
	logger := funcr.New(func(prefix, args string) { lines = append(lines, args) }, funcr.Options{})

	logDNSCoverage(logger, true)
	if len(lines) != 0 {
		t.Fatalf("with packet capture on it logged %v", lines)
	}
	logDNSCoverage(logger, false)
	if len(lines) != 1 || !strings.Contains(lines[0], "pure-Go resolver") || !strings.Contains(lines[0], "dnsPacketCapture") {
		t.Errorf("logged %v, want what is not seen and how to see it", lines)
	}
}
