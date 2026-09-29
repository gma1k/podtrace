package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestARunWithoutADeadlineCollectsForTheRequestedDuration(t *testing.T) {
	got, shortened := collectionWindow(20*time.Second, time.Time{}, time.Now())
	if got != 20*time.Second || shortened {
		t.Errorf("window = %v, shortened = %v", got, shortened)
	}
}

func TestADeadlineWithRoomToSpareLeavesTheDurationAlone(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	got, shortened := collectionWindow(20*time.Second, now.Add(time.Minute), now)
	if got != 20*time.Second || shortened {
		t.Errorf("window = %v, shortened = %v", got, shortened)
	}
}

func TestADeadlineTooCloseShortensTheCollectionAndKeepsTheReportMargin(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	got, shortened := collectionWindow(20*time.Second, now.Add(25*time.Second), now)
	if got != 10*time.Second || !shortened {
		t.Errorf("window = %v, shortened = %v; want the 25s left minus the 15s report margin", got, shortened)
	}
}

func TestASpentDeadlineStillCollectsBriefly(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	got, shortened := collectionWindow(20*time.Second, now.Add(-time.Minute), now)
	if got != minSessionCollection || !shortened {
		t.Errorf("window = %v, shortened = %v", got, shortened)
	}
}

func TestTheSessionDeadlineFlagIsParsed(t *testing.T) {
	if d, err := parseSessionDeadline(""); err != nil || !d.IsZero() {
		t.Errorf("empty = %v, %v", d, err)
	}
	if d, err := parseSessionDeadline("2026-09-29T12:00:50Z"); err != nil || d.Unix() != 1790683250 {
		t.Errorf("valid = %v, %v", d, err)
	}
	if _, err := parseSessionDeadline("soon"); err == nil {
		t.Error("an unparseable deadline was accepted")
	}
}

func TestADiagnoseCutShortByItsDeadlineSaysSoInTheReport(t *testing.T) {
	origDeadline, origExport := sessionDeadline, exportFormat
	defer func() { sessionDeadline, exportFormat = origDeadline, origExport }()
	exportFormat = ""
	sessionDeadline = time.Now().Add(sessionReportMargin + 200*time.Millisecond).UTC().Format(time.RFC3339Nano)

	eventChan := make(chan *events.Event, 1)
	stdoutMutex.Lock()
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	start := time.Now()
	err := runDiagnoseMode(context.Background(), eventChan, "10s", nil, nil, nil)
	elapsed := time.Since(start)
	_ = w.Close()
	os.Stdout = originalStdout
	stdoutMutex.Unlock()
	out, _ := io.ReadAll(r)

	if err != nil {
		t.Fatalf("runDiagnoseMode = %v", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("collected for %v; the deadline allowed well under a second", elapsed)
	}
	if !strings.Contains(string(out), "of the requested 10s") {
		t.Errorf("the report does not say it was cut short:\n%s", out)
	}
}

func TestAnInvalidSessionDeadlineFailsTheRun(t *testing.T) {
	orig := sessionDeadline
	defer func() { sessionDeadline = orig }()
	sessionDeadline = "soon"
	if err := runDiagnoseMode(context.Background(), make(chan *events.Event), "1s", nil, nil, nil); err == nil {
		t.Error("an unparseable deadline was accepted")
	}
}
