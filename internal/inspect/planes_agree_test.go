package inspect

import (
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/events"
)

func detectorSaturation(t *testing.T, pct int32) (detector.Issue, bool) {
	t.Helper()
	issues := detector.DetectIssues([]*events.Event{
		{Type: events.EventResourceLimit, Error: pct, TCPState: 0},
	}, 10, 1)
	for _, issue := range issues {
		if issue.ID == detector.IDResourceSaturation {
			return issue, true
		}
	}
	return detector.Issue{}, false
}

func inspectSaturation(t *testing.T, pct float64) (detector.Issue, bool) {
	t.Helper()
	cur := []*dto.MetricFamily{saturated(pct, "cpu", "pod-a")}
	for _, issue := range evalOnce(t, saturationRule(), nil, cur, time.Minute) {
		if issue.ID == detector.IDResourceSaturation {
			return issue, true
		}
	}
	return detector.Issue{}, false
}

func TestBothPlanesAgreeOnWhenSaturationFires(t *testing.T) {
	for _, pct := range []int{0, 10, 50, 79, 80, 84, 85, 89, 90, 94, 95, 99, 100, 140} {
		diagIssue, diagFired := detectorSaturation(t, int32(pct))
		contIssue, contFired := inspectSaturation(t, float64(pct))

		if diagFired != contFired {
			t.Errorf("at %d%% the diagnostic plane fired=%v but the continuous plane "+
				"fired=%v.\n\nThe same reading must mean the same thing on both planes, or "+
				"an operator gets a different answer depending on which one they asked.",
				pct, diagFired, contFired)
			continue
		}
		if !diagFired {
			continue
		}
		if diagIssue.Severity != contIssue.Severity {
			t.Errorf("at %d%% the planes disagree on severity: diagnostic=%q continuous=%q. "+
				"The operator's trigger machinery routes on severity, so the same reading "+
				"would reach different destinations.",
				pct, diagIssue.Severity, contIssue.Severity)
		}
		if diagIssue.ID != contIssue.ID {
			t.Errorf("at %d%% the planes emit different ids: %q vs %q",
				pct, diagIssue.ID, contIssue.ID)
		}
	}
}

func TestBothPlanesTrackTheSameConfiguredBands(t *testing.T) {
	originalWarn, originalCrit, originalEmerg :=
		config.AlertWarnPct, config.AlertCritPct, config.AlertEmergPct
	config.AlertWarnPct, config.AlertCritPct, config.AlertEmergPct = 55, 65, 75
	t.Cleanup(func() {
		config.AlertWarnPct, config.AlertCritPct, config.AlertEmergPct =
			originalWarn, originalCrit, originalEmerg
	})

	thresholds := Thresholds{
		ErrorRatePercent:     DefaultThresholds().ErrorRatePercent,
		MinRequestsPerSecond: DefaultThresholds().MinRequestsPerSecond,
		MeanLatency:          DefaultThresholds().MeanLatency,
		UtilizationWarn:      config.AlertWarnPct,
		UtilizationCritical:  config.AlertCritPct,
		UtilizationEmergency: config.AlertEmergPct,
	}

	for _, pct := range []int{50, 60, 70, 80} {
		diagIssue, diagFired := detectorSaturation(t, int32(pct))

		start := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
		snap, err := Take(&fixedGatherer{
			families: []*dto.MetricFamily{saturated(float64(pct), "cpu", "pod-a")},
		}, start)
		if err != nil {
			t.Fatalf("Take: %v", err)
		}
		var contIssue detector.Issue
		contFired := false
		for _, issue := range saturationRule().Eval(Window{Cur: snap}, thresholds) {
			contIssue, contFired = issue, true
		}

		if diagFired != contFired {
			t.Errorf("at %d%% with retuned bands: diagnostic fired=%v, continuous fired=%v; "+
				"a tuned PODTRACE_ALERT_*_PCT must move both planes together",
				pct, diagFired, contFired)
			continue
		}
		if diagFired && diagIssue.Severity != contIssue.Severity {
			t.Errorf("at %d%% with retuned bands the planes disagree on severity: %q vs %q",
				pct, diagIssue.Severity, contIssue.Severity)
		}
	}
}

func TestEveryIdSharedByBothPlanesIsRegisteredOnce(t *testing.T) {
	continuous := map[detector.ID]bool{}
	for _, rule := range Rules() {
		continuous[rule.ID] = true
	}

	diagnostic := map[detector.ID]bool{}
	for _, issue := range detector.DetectIssues([]*events.Event{
		{Type: events.EventConnect, Error: 1},
		{Type: events.EventConnect, Error: 1},
		{Type: events.EventTCPSend, LatencyNS: 900_000_000},
		{Type: events.EventTCPSend, LatencyNS: 900_000_000},
		{Type: events.EventResourceLimit, Error: 99, TCPState: 0},
	}, 10, 1) {
		diagnostic[issue.ID] = true
	}

	registered := map[detector.ID]bool{}
	for _, id := range detector.Registry {
		registered[id] = true
	}

	for id := range continuous {
		if !registered[id] {
			t.Errorf("continuous rule id %q is not in detector.Registry", id)
		}
	}
	for id := range diagnostic {
		if !registered[id] {
			t.Errorf("diagnostic issue id %q is not in detector.Registry", id)
		}
	}

	shared := 0
	for id := range continuous {
		if diagnostic[id] {
			shared++
		}
	}
	if shared == 0 {
		t.Error("no id is produced by both planes.\n\nAt least resource.saturation should " +
			"be, and if nothing is shared then the two planes have no common vocabulary " +
			"and the differential guarantee above is vacuous.")
	}
}

func detectorConnectionFailures(t *testing.T, total, failed int) (detector.Issue, bool) {
	t.Helper()
	var evts []*events.Event
	for i := 0; i < total; i++ {
		result := &events.Event{Type: events.EventConnectResult}
		if i < failed {
			result.Error = -111
		}
		evts = append(evts, &events.Event{Type: events.EventConnect}, result)
	}
	for _, issue := range detector.DetectIssues(evts, DefaultThresholds().ErrorRatePercent, 100) {
		if issue.ID == detector.IDConnectionFailureRate {
			return issue, true
		}
	}
	return detector.Issue{}, false
}

func inspectConnectionFailures(t *testing.T, total, failed int) (detector.Issue, bool) {
	t.Helper()
	cur := connections(float64(total), float64(failed))
	for _, issue := range evalOnce(t, connectionFailureRateRule(), nil, cur, time.Minute) {
		if issue.ID == detector.IDConnectionFailureRate {
			return issue, true
		}
	}
	return detector.Issue{}, false
}

func TestBothPlanesAgreeOnConnectionFailuresAboveTheTrafficFloor(t *testing.T) {
	for _, tc := range []struct{ total, failed int }{
		{100, 0}, {100, 1}, {100, 5}, {100, 6}, {100, 20}, {100, 50}, {100, 100},
		{60, 3}, {60, 4}, {600, 30}, {600, 31},
	} {
		diagIssue, diagFired := detectorConnectionFailures(t, tc.total, tc.failed)
		contIssue, contFired := inspectConnectionFailures(t, tc.total, tc.failed)

		if diagFired != contFired {
			t.Errorf("at %d/%d failures the diagnostic plane fired=%v but the continuous "+
				"plane fired=%v.\n\nAbove the traffic floor the same reading must mean the "+
				"same thing on both planes, or an operator gets a different answer depending "+
				"on which one they asked.", tc.failed, tc.total, diagFired, contFired)
			continue
		}
		if !diagFired {
			continue
		}
		if diagIssue.Severity != contIssue.Severity {
			t.Errorf("at %d/%d the planes disagree on severity: diagnostic=%q continuous=%q",
				tc.failed, tc.total, diagIssue.Severity, contIssue.Severity)
		}
		if diagIssue.ID != contIssue.ID {
			t.Errorf("at %d/%d the planes emit different ids: %q vs %q",
				tc.failed, tc.total, diagIssue.ID, contIssue.ID)
		}
	}
}

func TestTheContinuousPlaneAloneAppliesTheConnectionTrafficFloor(t *testing.T) {
	_, diagFired := detectorConnectionFailures(t, 4, 4)
	_, contFired := inspectConnectionFailures(t, 4, 4)

	if !diagFired {
		t.Error("the diagnostic plane did not fire on four failed connections out of four; " +
			"it has no traffic floor, so this documents the difference and must hold")
	}
	if contFired {
		t.Error("the continuous plane fired below its traffic floor. Without the floor a " +
			"single failed connect in an idle interval reads as a 100% failure rate and " +
			"pages someone for every idle workload in the cluster.")
	}
}
