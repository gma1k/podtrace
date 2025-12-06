package analyzer

import (
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestAnalyzeTLS(t *testing.T) {
	tests := []struct {
		name           string
		events         []*events.Event
		wantAvgLatency float64
		wantMaxLatency float64
		wantErrors     int
		wantP50        float64
		wantP95        float64
		wantP99        float64
	}{
		{
			name:           "empty events",
			events:         []*events.Event{},
			wantAvgLatency: 0,
			wantMaxLatency: 0,
			wantErrors:     0,
			wantP50:        0,
			wantP95:        0,
			wantP99:        0,
		},
		{
			name: "single successful handshake",
			events: []*events.Event{
				{
					Type:      events.EventTLSHandshake,
					LatencyNS: 100000000,
					Error:     0,
				},
			},
			wantAvgLatency: 100.0,
			wantMaxLatency: 100.0,
			wantErrors:     0,
			wantP50:        100.0,
			wantP95:        100.0,
			wantP99:        100.0,
		},
		{
			name: "multiple handshakes with errors",
			events: []*events.Event{
				{
					Type:      events.EventTLSHandshake,
					LatencyNS: 50000000,
					Error:     0,
					Target:    "example.com:443",
				},
				{
					Type:      events.EventTLSHandshake,
					LatencyNS: 200000000,
					Error:     -1,
					Target:    "bad.example.com:443",
				},
				{
					Type:      events.EventTLSHandshake,
					LatencyNS: 150000000,
					Error:     0,
					Target:    "example.com:443",
				},
			},
			wantAvgLatency: 133.33,
			wantMaxLatency: 200.0,
			wantErrors:     1,
			wantP50:        150.0,
			wantP95:        150.0,
			wantP99:        150.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			avgLatency, maxLatency, errors, p50, p95, p99, errorBreakdown, topTargets := AnalyzeTLS(tt.events)

			if errors != tt.wantErrors {
				t.Errorf("AnalyzeTLS() errors = %v, want %v", errors, tt.wantErrors)
			}

			if len(tt.events) == 0 {
				return
			}

			if avgLatency < tt.wantAvgLatency-1 || avgLatency > tt.wantAvgLatency+1 {
				t.Errorf("AnalyzeTLS() avgLatency = %v, want %v", avgLatency, tt.wantAvgLatency)
			}

			if maxLatency != tt.wantMaxLatency {
				t.Errorf("AnalyzeTLS() maxLatency = %v, want %v", maxLatency, tt.wantMaxLatency)
			}

			if p50 < tt.wantP50-1 || p50 > tt.wantP50+1 {
				t.Errorf("AnalyzeTLS() p50 = %v, want %v", p50, tt.wantP50)
			}

			if p95 < tt.wantP95-1 || p95 > tt.wantP95+1 {
				t.Errorf("AnalyzeTLS() p95 = %v, want %v", p95, tt.wantP95)
			}

			if p99 < tt.wantP99-1 || p99 > tt.wantP99+1 {
				t.Errorf("AnalyzeTLS() p99 = %v, want %v", p99, tt.wantP99)
			}

			if tt.wantErrors > 0 && len(errorBreakdown) == 0 {
				t.Errorf("AnalyzeTLS() expected error breakdown but got none")
			}

			if len(tt.events) > 1 && len(topTargets) == 0 {
				t.Errorf("AnalyzeTLS() expected top targets but got none")
			}
		})
	}
}

