package agent

import (
	"testing"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
)

func TestResourceSeverityFromUtilization(t *testing.T) {
	if _, ok := resourceSeverityFromUtilization(int32(config.AlertWarnPct - 1)); ok {
		t.Error("below warn floor must not alert")
	}
	if sev, ok := resourceSeverityFromUtilization(int32(config.AlertWarnPct)); !ok || sev != alerting.SeverityWarning {
		t.Errorf("at warn = (%q, %v), want warning, true", sev, ok)
	}
	if sev, ok := resourceSeverityFromUtilization(int32(config.AlertCritPct)); !ok || sev != alerting.SeverityCritical {
		t.Errorf("at crit = (%q, %v), want critical, true", sev, ok)
	}
	if sev, ok := resourceSeverityFromUtilization(int32(config.AlertEmergPct)); !ok || sev != alerting.SeverityFatal {
		t.Errorf("at emerg = (%q, %v), want fatal, true", sev, ok)
	}
}
