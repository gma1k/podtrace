package alerting

import (
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func TestSeverityFloorOrdersErrorBetweenWarningAndCritical(t *testing.T) {
	origEnabled := config.AlertingEnabled
	t.Cleanup(func() { config.AlertingEnabled = origEnabled })
	config.AlertingEnabled = true

	cases := []struct {
		floor string
		sent  map[AlertSeverity]bool
	}{
		{"", map[AlertSeverity]bool{SeverityWarning: true, SeverityError: true, SeverityCritical: true, SeverityFatal: true}},
		{"warning", map[AlertSeverity]bool{SeverityWarning: true, SeverityError: true, SeverityCritical: true, SeverityFatal: true}},
		{"error", map[AlertSeverity]bool{SeverityWarning: false, SeverityError: true, SeverityCritical: true, SeverityFatal: true}},
		{"critical", map[AlertSeverity]bool{SeverityWarning: false, SeverityError: false, SeverityCritical: true, SeverityFatal: true}},
		{"fatal", map[AlertSeverity]bool{SeverityWarning: false, SeverityError: false, SeverityCritical: false, SeverityFatal: true}},
		{"not-a-severity", map[AlertSeverity]bool{SeverityWarning: true, SeverityError: true, SeverityCritical: true, SeverityFatal: true}},
	}
	for _, tc := range cases {
		t.Run("floor="+tc.floor, func(t *testing.T) {
			t.Setenv("PODTRACE_ALERT_MIN_SEVERITY", tc.floor)
			for severity, want := range tc.sent {
				if got := ShouldSendAlert(severity); got != want {
					t.Errorf("ShouldSendAlert(%s) at floor %q = %v, want %v", severity, tc.floor, got, want)
				}
			}
		})
	}
}

func TestAnErrorLogAlertPassesTheDefaultFloor(t *testing.T) {
	origEnabled := config.AlertingEnabled
	t.Cleanup(func() { config.AlertingEnabled = origEnabled })
	config.AlertingEnabled = true
	t.Setenv("PODTRACE_ALERT_MIN_SEVERITY", "warning")

	if !ShouldSendAlert(SeverityError) {
		t.Fatal("a logger.Error alert is dropped at the default warning floor while warnings are sent")
	}
}
