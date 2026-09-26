package export

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func csvDiagnostician(evs ...*events.Event) *mockDiagnostician {
	return &mockDiagnostician{events: evs, startTime: time.Now(), endTime: time.Now().Add(time.Second)}
}

func TestACSVExportToAFailingDestinationReportsTheFailure(t *testing.T) {
	err := ExportCSV(csvDiagnostician(&events.Event{Type: events.EventTCPSend, Target: "10.0.0.1:80"}), failingWriter{})
	if err == nil {
		t.Error("ExportCSV returned nil although nothing could be written.\n\n" +
			"csv.Writer buffers, so a small export fails only at the final flush. The " +
			"flush ran in a defer that dropped its error, and a caller writing a report " +
			"to a full disk was told the export succeeded.")
	}
}

func TestACSVRecordLargerThanTheBufferFailsMidExport(t *testing.T) {
	big := &events.Event{Type: events.EventTCPSend, Target: strings.Repeat("x", 8192)}
	if err := ExportCSV(csvDiagnostician(big), failingWriter{}); err == nil {
		t.Error("a record that spills the writer's buffer into a failing destination returned nil")
	}
}
