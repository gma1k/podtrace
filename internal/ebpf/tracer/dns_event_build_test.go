package tracer

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/dns"
	"github.com/gma1k/podtrace/internal/events"
)

func TestDNSResolvedValue(t *testing.T) {
	b := dnsResolvedValue("example.com")
	if got := string(b[:len("example.com")]); got != "example.com" {
		t.Errorf("name not copied: %q", got)
	}
	if b[dnsResolvedNameLen-1] != 0 {
		t.Error("final byte must stay NUL")
	}

	long := dnsResolvedValue(strings.Repeat("a", 300))
	if long[dnsResolvedNameLen-1] != 0 {
		t.Error("truncated value must keep the final NUL")
	}
	for i := 0; i < dnsResolvedNameLen-1; i++ {
		if long[i] != 'a' {
			t.Fatalf("byte %d = %d, want 'a'", i, long[i])
		}
	}
}

func TestBuildDNSEventFromRecord_ResolvedIPsJoined(t *testing.T) {
	rec := dns.Record{
		CgroupID:  42,
		PID:       7,
		Timestamp: 100,
		LatencyNS: 5,
		QType:     1,
		Msg: dns.Message{
			QName:   "svc.local",
			Answers: []dns.Answer{{IP: "10.0.0.1"}, {IP: "10.0.0.2"}, {IP: "10.0.0.1"}},
		},
	}
	e := buildDNSEventFromRecord(rec)
	if e.Type != events.EventDNS || e.CgroupID != 42 || e.PID != 7 {
		t.Errorf("header fields wrong: %+v", e)
	}
	if e.Target != "svc.local" {
		t.Errorf("Target = %q", e.Target)
	}
	if e.Details != "10.0.0.1, 10.0.0.2" {
		t.Errorf("Details = %q, want deduplicated joined IPs", e.Details)
	}
}

func TestBuildDNSEventFromRecord_CNAMEFallback(t *testing.T) {
	rec := dns.Record{
		Msg: dns.Message{
			QName:   "alias.example",
			Answers: []dns.Answer{{IP: ""}, {CNAME: "canonical.example"}},
		},
	}
	e := buildDNSEventFromRecord(rec)
	if e.Details != "canonical.example" {
		t.Errorf("Details = %q, want CNAME fallback", e.Details)
	}
}
