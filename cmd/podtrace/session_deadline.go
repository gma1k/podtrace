package main

import (
	"fmt"
	"time"
)

// sessionReportMargin is the time kept before the deadline to write, export
// and upload the report.
const sessionReportMargin = 15 * time.Second

// minSessionCollection is the shortest collection a run still makes when the
// deadline is nearly spent, so that the report has something in it.
const minSessionCollection = time.Second

// parseSessionDeadline reads the --session-deadline flag; an empty flag means
// the run has no deadline.
func parseSessionDeadline(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid --session-deadline %q: %w", s, err)
	}
	return t, nil
}

// collectionWindow returns how long to collect, and whether that is less than
// was requested because the deadline leaves no more time.
func collectionWindow(requested time.Duration, deadline, now time.Time) (time.Duration, bool) {
	if deadline.IsZero() {
		return requested, false
	}
	left := deadline.Sub(now) - sessionReportMargin
	if left >= requested {
		return requested, false
	}
	if left < minSessionCollection {
		left = minSessionCollection
	}
	return left, true
}

// shortenedCollectionNote heads a report whose collection was cut short.
func shortenedCollectionNote(requested, collected time.Duration) string {
	return fmt.Sprintf("Note: collected for %s of the requested %s. Starting the trace took long enough "+
		"that collecting for longer would have run past the session's deadline; raise the TracerConfig's "+
		"spec.session.activeDeadlineOffset to give sessions more time.\n\n",
		collected.Round(time.Second), requested.Round(time.Second))
}
