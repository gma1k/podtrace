package diagnose

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

func TestGenerateReport_HonorsConfiguredTimeout(t *testing.T) {
	orig := config.ReportGenerationTimeout
	config.ReportGenerationTimeout = time.Nanosecond
	defer func() { config.ReportGenerationTimeout = orig }()

	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventHTTPReq})

	report := d.GenerateReport()
	if !strings.Contains(report, "cancelled") {
		t.Fatalf("GenerateReport ignored the configured deadline; got %q", report)
	}
}
