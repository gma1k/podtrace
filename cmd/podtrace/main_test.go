package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/diagnose"
	"github.com/podtrace/podtrace/internal/events"
)

func TestFilterEvents(t *testing.T) {
	tests := []struct {
		name     string
		filter   string
		events   []*events.Event
		expected int
	}{
		{
			name:   "dns filter",
			filter: "dns",
			events: []*events.Event{
				{Type: events.EventDNS},
				{Type: events.EventConnect},
				{Type: events.EventDNS},
			},
			expected: 2,
		},
		{
			name:   "net filter",
			filter: "net",
			events: []*events.Event{
				{Type: events.EventConnect},
				{Type: events.EventTCPSend},
				{Type: events.EventDNS},
			},
			expected: 2,
		},
		{
			name:   "fs filter",
			filter: "fs",
			events: []*events.Event{
				{Type: events.EventRead},
				{Type: events.EventWrite},
				{Type: events.EventConnect},
			},
			expected: 2,
		},
		{
			name:   "cpu filter",
			filter: "cpu",
			events: []*events.Event{
				{Type: events.EventSchedSwitch},
				{Type: events.EventConnect},
			},
			expected: 1,
		},
		{
			name:   "proc filter",
			filter: "proc",
			events: []*events.Event{
				{Type: events.EventExec},
				{Type: events.EventFork},
				{Type: events.EventConnect},
			},
			expected: 2,
		},
		{
			name:   "multiple filters",
			filter: "dns,net",
			events: []*events.Event{
				{Type: events.EventDNS},
				{Type: events.EventConnect},
				{Type: events.EventRead},
			},
			expected: 2,
		},
		{
			name:   "empty filter",
			filter: "",
			events: []*events.Event{
				{Type: events.EventDNS},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := make(chan *events.Event, len(tt.events))
			out := make(chan *events.Event, len(tt.events))

			go func() {
				defer close(in)
				for _, e := range tt.events {
					in <- e
				}
			}()

			go filterEvents(in, out, tt.filter)

			count := 0
			for range out {
				count++
			}

			if count != tt.expected {
				t.Errorf("Expected %d events, got %d", tt.expected, count)
			}
		})
	}
}

func TestFilterEvents_NilEvent(t *testing.T) {
	in := make(chan *events.Event, 1)
	out := make(chan *events.Event, 1)

	go func() {
		defer close(in)
		in <- nil
		in <- &events.Event{Type: events.EventDNS}
	}()

	go filterEvents(in, out, "dns")

	count := 0
	for range out {
		count++
	}

	if count != 1 {
		t.Errorf("Expected 1 event (nil should be filtered), got %d", count)
	}
}

func TestExportReport_JSON(t *testing.T) {
	d := diagnose.NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"})
	d.Finish()

	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := exportReport("test report", "json", d)
	w.Close()
	os.Stdout = originalStdout

	if err == nil {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		t.Logf("JSON export test completed, output length: %d", buf.Len())
	}
}

func TestExportReport_CSV(t *testing.T) {
	d := diagnose.NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"})
	d.Finish()

	var buf bytes.Buffer
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := exportReport("test report", "csv", d)
	w.Close()
	os.Stdout = originalStdout

	if err == nil {
		io.Copy(&buf, r)
		t.Logf("CSV export test completed, output length: %d", buf.Len())
	}
}

func TestExportReport_InvalidFormat(t *testing.T) {
	d := diagnose.NewDiagnostician()
	err := exportReport("test report", "invalid", d)

	if err == nil {
		t.Error("Expected error for invalid format")
	}

	if err != nil && !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("Expected error message to contain 'unsupported', got: %v", err)
	}
}

