package diagnose

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/logger"
)

func TestASamplingDiagnosticianSaysSoOnceAMinuteAtMost(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1
	d.sampleIntN = reject
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	add := func(n int) {
		for i := 0; i < n; i++ {
			d.AddEvent(&events.Event{Type: events.EventTCPRecv})
		}
	}
	add(2)
	if d.lastSamplingNotice != now {
		t.Fatalf("first sampled-out event was not announced: last notice %v", d.lastSamplingNotice)
	}
	first := now
	now = now.Add(samplingNoticeInterval - time.Second)
	add(50_000)
	if d.lastSamplingNotice != first {
		t.Errorf("announced again after %v", now.Sub(first))
	}
	now = now.Add(2 * time.Second)
	add(1)
	if d.lastSamplingNotice != now {
		t.Errorf("not announced again after %v", now.Sub(first))
	}
}

func TestTheSamplingNoticeUsesTheWallClockByDefault(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1
	d.sampleIntN = reject
	before := time.Now()
	d.AddEvent(&events.Event{Type: events.EventTCPRecv})
	d.AddEvent(&events.Event{Type: events.EventTCPRecv})
	if d.lastSamplingNotice.Before(before) {
		t.Errorf("last notice %v predates the events", d.lastSamplingNotice)
	}
}

func TestAFullBufferRaisesNoAlert(t *testing.T) {
	got := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		got <- fmt.Sprint(payload["message"])
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	origEnabled, origURL := config.AlertingEnabled, config.AlertWebhookURL
	t.Setenv("PODTRACE_ALERT_MIN_SEVERITY", "warning")
	config.AlertingEnabled, config.AlertWebhookURL = true, srv.URL
	manager, err := alerting.NewManager()
	if err != nil {
		t.Fatal(err)
	}
	if !manager.IsEnabled() {
		t.Skip("manager disabled")
	}
	alerting.SetGlobalManager(manager)
	t.Cleanup(func() {
		alerting.SetGlobalManager(nil)
		config.AlertingEnabled, config.AlertWebhookURL = origEnabled, origURL
	})

	d := NewDiagnostician()
	d.maxEvents = 1
	d.sampleIntN = reject
	for i := 0; i < 30_000; i++ {
		d.AddEvent(&events.Event{Type: events.EventTCPRecv})
	}
	logger.Warn("sentinel after the buffer filled")
	for {
		select {
		case msg := <-got:
			if msg == "sentinel after the buffer filled" {
				return
			}
			t.Errorf("a full buffer raised an alert: %q", msg)
		case <-time.After(5 * time.Second):
			t.Fatal("the sentinel alert never arrived")
		}
	}
}
