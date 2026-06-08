package report

import (
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestFormatFastCGIActivity(t *testing.T) {
	duration := 5 * time.Second

	t.Run("empty returns blank", func(t *testing.T) {
		d := &mockDiagnostician{events: []*events.Event{}}
		if got := formatFastCGIActivity(d, duration); got != "" {
			t.Errorf("expected empty string for no FastCGI events, got %q", got)
		}
	})

	t.Run("no fastcgi events among others returns blank", func(t *testing.T) {
		d := &mockDiagnostician{events: []*events.Event{
			{Type: events.EventDNS, Target: "example.com"},
			{Type: events.EventTCPSend},
		}}
		if got := formatFastCGIActivity(d, duration); got != "" {
			t.Errorf("expected empty string when no FastCGI events present, got %q", got)
		}
	})

	t.Run("full activity exercises every branch", func(t *testing.T) {
		var evs []*events.Event

		reqs := []*events.Event{
			{Type: events.EventFastCGIReq, PID: 100, ProcessName: "php-fpm", Details: "GET", Target: "/index.php", Timestamp: 1_000_000_000},
			{Type: events.EventFastCGIReq, PID: 100, ProcessName: "php-fpm", Details: "GET", Target: "/index.php", Timestamp: 1_100_000_000},
			{Type: events.EventFastCGIReq, PID: 100, ProcessName: "php-fpm", Details: "POST", Target: "/api/submit", Timestamp: 1_200_000_000},
			{Type: events.EventFastCGIReq, PID: 200, ProcessName: "php-fpm", Details: "GET /noise\x00", Target: "/admin\x01", Timestamp: 1_300_000_000},
			{Type: events.EventFastCGIReq, PID: 200, ProcessName: "", Details: "GET", Target: "", Timestamp: 1_400_000_000},
			{Type: events.EventFastCGIReq, PID: 300, ProcessName: "php-fpm", Details: "PUT", Target: "/index.php", Timestamp: 1_500_000_000},
		}
		evs = append(evs, reqs...)

		resps := []*events.Event{
			{Type: events.EventFastCGIResp, PID: 100, Target: "/index.php", LatencyNS: 500_000, Timestamp: 1_050_000_000},                 // <1ms
			{Type: events.EventFastCGIResp, PID: 100, Target: "/index.php", LatencyNS: 5_000_000, Timestamp: 1_150_000_000},               // 1-10ms
			{Type: events.EventFastCGIResp, PID: 100, Target: "/api/submit", LatencyNS: 50_000_000, Timestamp: 1_250_000_000, Error: 500}, // 10-100ms, error
			{Type: events.EventFastCGIResp, PID: 200, Target: "/admin\x01", LatencyNS: 250_000_000, Timestamp: 1_350_000_000, Error: 502}, // >100ms, error
			{Type: events.EventFastCGIResp, PID: 200, Target: "", LatencyNS: 800_000, Timestamp: 1_450_000_000},                           // <1ms, URI "/"
			{Type: events.EventFastCGIResp, PID: 300, Target: "/index.php", LatencyNS: 9_000_000, Timestamp: 1_550_000_000},               // 1-10ms
		}
		evs = append(evs, resps...)

		d := &mockDiagnostician{events: evs}
		got := formatFastCGIActivity(d, duration)

		if got == "" {
			t.Fatal("expected non-empty output")
		}

		mustContain := []string{
			"FastCGI Activity:",
			"Requests:",
			"Responses:",
			"Methods:",
			"Workers:",
			"Top URIs:",
			"Latency distribution:",
			"Recent events:",
		}
		for _, s := range mustContain {
			if !strings.Contains(got, s) {
				t.Errorf("expected output to contain %q\n--- output ---\n%s", s, got)
			}
		}

		if !strings.Contains(got, "GET: 4") {
			t.Errorf("expected method breakdown 'GET: 4'\n--- output ---\n%s", got)
		}
		if !strings.Contains(got, "POST: 1") {
			t.Errorf("expected method breakdown 'POST: 1'\n--- output ---\n%s", got)
		}

		if !strings.Contains(got, "PID 100 (php-fpm): 3 req") {
			t.Errorf("expected worker line for PID 100\n--- output ---\n%s", got)
		}

		if !strings.Contains(got, "/index.php") {
			t.Errorf("expected /index.php in Top URIs\n--- output ---\n%s", got)
		}
		if !strings.Contains(got, "p50=") || !strings.Contains(got, "p95=") ||
			!strings.Contains(got, "p99=") || !strings.Contains(got, "max=") {
			t.Errorf("expected latency percentiles in Top URIs\n--- output ---\n%s", got)
		}
		if !strings.Contains(got, "errors=") {
			t.Errorf("expected errors=N in Top URIs (app errors present)\n--- output ---\n%s", got)
		}

		if !strings.Contains(got, "/") {
			t.Errorf("expected empty URI rendered as '/'\n--- output ---\n%s", got)
		}

		for _, b := range []string{"<1ms:", "1-10ms:", "10-100ms:", ">100ms:"} {
			if !strings.Contains(got, b) {
				t.Errorf("expected latency bucket %q\n--- output ---\n%s", b, got)
			}
		}

		if !strings.Contains(got, "RESP") {
			t.Errorf("expected RESP samples in Recent events\n--- output ---\n%s", got)
		}
		if !strings.Contains(got, "status=") {
			t.Errorf("expected status= in RESP samples\n--- output ---\n%s", got)
		}

		sampleLines := 0
		for _, ln := range strings.Split(got, "\n") {
			if strings.HasPrefix(ln, "    +") {
				sampleLines++
			}
		}
		if sampleLines != 10 {
			t.Errorf("expected exactly 10 recent-event sample lines, got %d\n--- output ---\n%s", sampleLines, got)
		}
	})

	t.Run("requests only no responses", func(t *testing.T) {
		d := &mockDiagnostician{events: []*events.Event{
			{Type: events.EventFastCGIReq, PID: 1, ProcessName: "php-fpm", Details: "GET", Target: "/", Timestamp: 1_000_000_000},
		}}
		got := formatFastCGIActivity(d, duration)
		if !strings.Contains(got, "Requests:") {
			t.Errorf("expected Requests section\n%s", got)
		}
		if strings.Contains(got, "Latency distribution:") {
			t.Errorf("did not expect latency distribution without responses\n%s", got)
		}
		if strings.Contains(got, "Responses:") {
			t.Errorf("did not expect Responses line without responses\n%s", got)
		}
	})

	t.Run("responses only no requests", func(t *testing.T) {
		d := &mockDiagnostician{events: []*events.Event{
			{Type: events.EventFastCGIResp, PID: 1, Target: "/", LatencyNS: 2_000_000, Timestamp: 1_000_000_000},
		}}
		got := formatFastCGIActivity(d, duration)
		if !strings.Contains(got, "Responses:") {
			t.Errorf("expected Responses section\n%s", got)
		}
		if strings.Contains(got, "Requests:") {
			t.Errorf("did not expect Requests line without requests\n%s", got)
		}
		if !strings.Contains(got, "Latency distribution:") {
			t.Errorf("expected latency distribution with responses\n%s", got)
		}
	})
}
