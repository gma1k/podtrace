package report

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

func letters(n int) string {
	var b strings.Builder
	for {
		b.WriteByte(byte('A' + n%26))
		n /= 26
		if n == 0 {
			return b.String()
		}
	}
}

func TestClientChosenFastCGIMethodsAreListedTopFirstAndCapped(t *testing.T) {
	const distinct = 60_000
	evs := make([]*events.Event, 0, distinct+3)
	for i := range distinct {
		evs = append(evs, &events.Event{Type: events.EventFastCGIReq, Details: "X" + letters(i), Target: "/", Timestamp: uint64(i + 1)})
	}
	for range 3 {
		evs = append(evs, &events.Event{Type: events.EventFastCGIReq, Details: "GET", Target: "/", Timestamp: 1})
	}
	d := &mockDiagnostician{events: evs}

	start := time.Now()
	got := formatFastCGIActivity(d, time.Second)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("rendering took %v", elapsed)
	}
	if len(got) > 16<<10 {
		t.Errorf("section is %d bytes; it must not grow with the number of methods clients invent", len(got))
	}
	methods := got[strings.Index(got, "  Methods:\n"):strings.Index(got, "  Workers:\n")]
	if !strings.HasPrefix(methods, "  Methods:\n    GET: 3\n") {
		t.Errorf("the most frequent method is not listed first:\n%s", methods)
	}
	want := fmt.Sprintf("    (%d more methods)\n", distinct+1-config.TopProcessesLimit)
	if !strings.HasSuffix(methods, want) {
		t.Errorf("methods section does not end with %q:\n%s", want, methods)
	}
	if lines := strings.Count(methods, "\n"); lines != config.TopProcessesLimit+2 {
		t.Errorf("methods section has %d lines, want %d", lines, config.TopProcessesLimit+2)
	}
}

func TestAFewFastCGIMethodsAreAllListed(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		{Type: events.EventFastCGIReq, Details: "GET", Target: "/"},
		{Type: events.EventFastCGIReq, Details: "POST", Target: "/"},
	}}
	got := formatFastCGIActivity(d, time.Second)
	if strings.Contains(got, "more methods") || !strings.Contains(got, "    GET: 1\n    POST: 1\n") {
		t.Errorf("section = %q", got)
	}
}

func TestAURIRequestedWithSeveralMethodsIsLabelledMixed(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		{Type: events.EventFastCGIReq, Details: "GET", Target: "/a"},
		{Type: events.EventFastCGIReq, Details: "POST", Target: "/a"},
		{Type: events.EventFastCGIReq, Details: "GET", Target: "/b"},
		{Type: events.EventFastCGIReq, Details: "GET", Target: "/b"},
	}}
	got := formatFastCGIActivity(d, time.Second)
	if !strings.Contains(got, "    - (mixed) /a: 2 req") || !strings.Contains(got, "    - GET /b: 2 req") {
		t.Errorf("URI lines do not say which method, or that there were several:\n%s", got)
	}
}
