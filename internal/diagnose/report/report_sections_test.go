package report

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

type filterDiagnostician struct {
	byType    map[events.EventType][]*events.Event
	startTime time.Time
	endTime   time.Time
}

func (f *filterDiagnostician) GetEvents() []*events.Event {
	var all []*events.Event
	for _, evs := range f.byType {
		all = append(all, evs...)
	}
	return all
}
func (f *filterDiagnostician) FilterEvents(t events.EventType) []*events.Event { return f.byType[t] }
func (f *filterDiagnostician) CalculateRate(count int, duration time.Duration) float64 {
	if duration.Seconds() > 0 {
		return float64(count) / duration.Seconds()
	}
	return 0
}
func (f *filterDiagnostician) StartTime() time.Time        { return f.startTime }
func (f *filterDiagnostician) EndTime() time.Time          { return f.endTime }
func (f *filterDiagnostician) ErrorRateThreshold() float64 { return 0 }
func (f *filterDiagnostician) RTTSpikeThreshold() float64  { return 0 }
func (f *filterDiagnostician) FSSlowThreshold() float64    { return 0 }

func TestFormatFastCGIActivity_NilEntriesAndURICap(t *testing.T) {
	reqs := []*events.Event{nil}
	resps := []*events.Event{nil}

	for i := 0; i < config.TopProcessesLimit+4; i++ {
		uri := "/path" + strconv.Itoa(i)
		reqs = append(reqs, &events.Event{
			Type: events.EventFastCGIReq, PID: uint32(i + 1), Details: "GET", Target: uri,
			Timestamp: uint64(1_000_000_000 + i),
		})
		resps = append(resps, &events.Event{
			Type: events.EventFastCGIResp, PID: uint32(i + 1), Target: uri,
			LatencyNS: uint64(1_000_000 * (i + 1)), Timestamp: uint64(1_000_000_500 + i),
		})
	}
	d := &filterDiagnostician{
		byType: map[events.EventType][]*events.Event{
			events.EventFastCGIReq:  reqs,
			events.EventFastCGIResp: resps,
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	out := formatFastCGIActivity(d, time.Second)
	if !strings.Contains(out, "FastCGI Activity") {
		t.Fatalf("expected FastCGI activity output, got %q", out)
	}
	if !strings.Contains(out, "Top URIs:") {
		t.Errorf("expected Top URIs section, got:\n%s", out)
	}

	uriLines := strings.Count(out, "    - GET /path")
	if uriLines != config.TopProcessesLimit {
		t.Errorf("expected Top URIs capped at %d, got %d\n%s", config.TopProcessesLimit, uriLines, out)
	}
}

func TestGenerateHTTP3Section_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{{Type: events.EventDNS}},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	if out := GenerateHTTP3Section(d, time.Second); out != "" {
		t.Errorf("expected empty HTTP/3 section with no HTTP/3 events, got %q", out)
	}
}

func TestGenerateHTTP3Section_PeersSNIAndALPN(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{

			{Type: events.EventHTTP3, Target: "cdn.example.com:443", Details: "sni: cdn.example.com alpn: h3,h3-29"},
			{Type: events.EventHTTP3, Target: "cdn.example.com:443", Details: "sni: cdn.example.com alpn: h3,h3-29"},

			{Type: events.EventHTTP3, Target: "api.example.com:443", Details: "sni: api.example.com"},

			{Type: events.EventHTTP3, Target: "plain.example.com:443", Details: "not-an-sni-line"},

			{Type: events.EventHTTP3, Target: "", Details: "sni: notarget.example.com alpn: h3"},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	out := GenerateHTTP3Section(d, time.Second)
	if out == "" {
		t.Fatal("expected non-empty HTTP/3 section")
	}
	for _, want := range []string{
		"HTTP/3 (QUIC) Connections:",
		"Connections: 5",
		"h3 peers",
		"h3 server names (SNI)",
		"h3 ALPN protocols",
		"cdn.example.com",
		"h3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected HTTP/3 section to contain %q\n--- output ---\n%s", want, out)
		}
	}

	if strings.Contains(out, ":0") {
		t.Errorf("did not expect a zero-port peer entry\n%s", out)
	}
}

func TestGenerateDNSSection_RCodeBreakdown(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{

			{Type: events.EventDNS, Target: "broken.example.com", LatencyNS: 2_000_000, Error: 3, TCPState: 1},
			{Type: events.EventDNS, Target: "ok.example.com", LatencyNS: 1_000_000, Error: 0, TCPState: 28},
			{Type: events.EventDNSQuery, Target: "broken.example.com"},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	out := GenerateDNSSection(d, time.Second)
	if !strings.Contains(out, "Response code breakdown:") {
		t.Errorf("expected DNS response code breakdown, got:\n%s", out)
	}
	if !strings.Contains(out, "Query type breakdown:") {
		t.Errorf("expected DNS query type breakdown, got:\n%s", out)
	}
}

func TestGenerateHTTPSection_ResponseStatusAndPeers(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventHTTPReq, Target: "/api", PeerDstIP: "10.1.2.3", PeerDstPort: 8080},

			{
				Type:        events.EventHTTPResp,
				Target:      "/api",
				Details:     "200\ncontent-type: application/json",
				LatencyNS:   3_000_000,
				Bytes:       128,
				PeerDstIP:   "10.1.2.3",
				PeerDstPort: 8080,
			},

			{
				Type:      events.EventHTTPResp,
				Target:    "/broken",
				Details:   "",
				Error:     503,
				LatencyNS: 9_000_000,
			},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	out := GenerateHTTPSection(d, time.Second)
	for _, want := range []string{
		"HTTP",
		"-> 200",
		"response status codes",
		"L7 peers",
		"10.1.2.3:8080",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected HTTP section to contain %q\n--- output ---\n%s", want, out)
		}
	}
	if !strings.Contains(out, "503") {
		t.Errorf("expected Error-derived status 503 in output\n%s", out)
	}
}

func TestResponseStatus_EdgeCases(t *testing.T) {
	cases := []struct {
		name  string
		event *events.Event
		want  string
	}{
		{"first-line status", &events.Event{Details: "404\nX-Header: y"}, "404"},
		{"single-line status", &events.Event{Details: "201"}, "201"},
		{"error fallback", &events.Event{Details: "not-a-code", Error: 500}, "500"},
		{"none", &events.Event{Details: "garbage", Error: 42}, ""},
	}
	for _, c := range cases {
		if got := responseStatus(c.event); got != c.want {
			t.Errorf("%s: responseStatus() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestGeneratePoolSection_ExhaustedNoAcquires(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{

			{Type: events.EventPoolRelease, Target: "pool-x"},
			{Type: events.EventPoolExhausted, Target: "pool-x", LatencyNS: 4_000_000},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	out := GeneratePoolSection(d, time.Second)
	if !strings.Contains(out, "CRITICAL - Pool exhausted with no successful acquisitions") {
		t.Errorf("expected CRITICAL pool-health status for exhaustion with no acquires, got:\n%s", out)
	}
}
