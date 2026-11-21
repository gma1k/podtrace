package diagnose

import (
	"context"
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

func TestAReportCutShortKeepsItsSectionsAndSaysWhereItStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var ran []string
	section := func(name string, after func()) func() string {
		return func() string {
			ran = append(ran, name)
			if after != nil {
				after()
			}
			return name + "\n"
		}
	}
	got := writeSections(ctx, []func() string{section("first", nil), section("second", cancel), section("third", nil)})
	if !strings.HasPrefix(got, "first\nsecond\n") || !strings.Contains(got, "the sections after this point were not generated") {
		t.Errorf("report = %q", got)
	}
	if len(ran) != 2 {
		t.Errorf("ran %v after the deadline passed", ran)
	}
}

func TestAReportWhoseDeadlinePassedBeforeItStartedIsOnlyTheNotice(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := writeSections(ctx, []func() string{func() string { return "x" }})
	if got != "Report generation cancelled: context canceled\n" {
		t.Errorf("report = %q", got)
	}
}

func TestAReportWithoutAnErrorCorrelatorStillCompletes(t *testing.T) {
	d := NewDiagnostician()
	d.errorCorrelator = nil
	d.AddEvent(&events.Event{Type: events.EventConnect, Error: -111, Target: "10.0.0.1:80"})
	d.Finish()
	if got := d.GenerateReport(); strings.Contains(got, "cancelled") || strings.Contains(got, "Error Correlation") {
		t.Errorf("report = %q", got)
	}
}
