package report

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/diagnose/analyzer"
	"github.com/gma1k/podtrace/internal/events"
)

func TestUDPErrorsLeaveOutEAGAINAndKernelRestarts(t *testing.T) {
	_, _, errs, _, _ := analyzeUDPEvents([]*events.Event{
		{Type: events.EventUDPRecv, Error: -11},
		{Type: events.EventUDPRecv, Error: -512},
		{Type: events.EventUDPSend, Error: -111},
		{Type: events.EventUDPSend},
	})
	if errs != 1 {
		t.Errorf("UDP errors = %d, want 1", errs)
	}
}

func TestTCPErrorsLeaveOutKernelRestarts(t *testing.T) {
	_, _, _, _, _, _, errs, _, _, _ := analyzer.AnalyzeTCP([]*events.Event{
		{Type: events.EventTCPRecv, Error: -11},
		{Type: events.EventTCPSend, Error: -512},
		{Type: events.EventTCPSend, Error: -104},
	}, 100)
	if errs != 1 {
		t.Errorf("TCP errors = %d, want 1", errs)
	}
}

func TestTheTCPAndUDPSectionsAgreeOnWhatAFailureIs(t *testing.T) {
	d := &mockDiagnostician{rttSpikeThreshold: 100, events: []*events.Event{
		{Type: events.EventTCPRecv, Error: -11},
		{Type: events.EventTCPRecv, Error: -104},
		{Type: events.EventUDPRecv, Error: -11},
		{Type: events.EventUDPRecv, Error: -111},
	}}
	tcp := GenerateTCPSection(d, time.Second)
	udp := GenerateUDPSection(d, time.Second)
	if !strings.Contains(tcp, "Errors: 1 (50.0%)") {
		t.Errorf("TCP section = %q, want one error of two", tcp)
	}
	if !strings.Contains(udp, "Errors: 1 (50.0%)") {
		t.Errorf("UDP section = %q, want one error of two", udp)
	}
}
