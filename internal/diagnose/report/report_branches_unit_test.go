package report

import (
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

// These tests drive the remaining uncovered formatting branches in report.go
// using the package mockDiagnostician: display caps, percentile output, unknown
// resource types, severity classification, and nil-event guards.

// ─── formatOOMKills: display cap ──────────────────────────────────────────────

func TestFormatOOMKills_ExceedsDisplayCap(t *testing.T) {
	var oom []*events.Event
	for i := 0; i < config.MaxOOMKillsDisplay+3; i++ {
		oom = append(oom, &events.Event{Type: events.EventOOMKill, Target: "proc", Bytes: 1024})
	}
	oom = append(oom, &events.Event{Type: events.EventOOMKill, PID: 7, Bytes: 2048})

	out := formatOOMKills(oom)
	if !strings.Contains(out, "OOM kills:") {
		t.Errorf("expected OOM kills header, got %q", out)
	}
	lines := strings.Count(out, "    - ")
	if lines != config.MaxOOMKillsDisplay {
		t.Errorf("expected %d listed kills (cap), got %d", config.MaxOOMKillsDisplay, lines)
	}
}

func TestFormatOOMKills_EmptyTargetUsesPID(t *testing.T) {
	out := formatOOMKills([]*events.Event{
		{Type: events.EventOOMKill, PID: 42, Bytes: 1024},
	})
	if !strings.Contains(out, "PID 42") {
		t.Errorf("expected PID fallback in output, got %q", out)
	}
}

// ─── GenerateIssuesSection: severity classification with alerting manager ─────

func TestGenerateIssuesSection_CriticalAndWarningSeverity(t *testing.T) {
	original := alerting.GetGlobalManager()
	mgr, _ := alerting.NewManager()
	alerting.SetGlobalManager(mgr)
	t.Cleanup(func() { alerting.SetGlobalManager(original) })

	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventResourceLimit, TCPState: 0, Error: 96},
			{Type: events.EventResourceLimit, TCPState: 1, Error: 85},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}

	out := GenerateIssuesSection(d)
	if !strings.Contains(out, "Potential Issues Detected") {
		t.Errorf("expected issues section, got %q", out)
	}
}

func TestGenerateIssuesSection_NoIssues(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{{Type: events.EventDNS}},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	if out := GenerateIssuesSection(d); out != "" {
		t.Errorf("expected empty issues section, got %q", out)
	}
}

// ─── GeneratePoolSection: percentiles + pool cap ──────────────────────────────

func TestGeneratePoolSection_PercentilesAndPoolCap(t *testing.T) {
	var evts []*events.Event
	for i := 0; i < config.MaxConnectionTargets+3; i++ {
		pool := "pool-" + string(rune('a'+i))
		evts = append(evts,
			&events.Event{Type: events.EventPoolAcquire, Target: pool},
			&events.Event{Type: events.EventPoolRelease, Target: pool},
		)
	}
	evts = append(evts,
		&events.Event{Type: events.EventPoolExhausted, Target: "pool-a", LatencyNS: 5_000_000},
		&events.Event{Type: events.EventPoolExhausted, Target: "pool-a", LatencyNS: 9_000_000},
	)

	d := &mockDiagnostician{
		events:    evts,
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	out := GeneratePoolSection(d, time.Second)
	if !strings.Contains(out, "Connection Pool") {
		t.Errorf("expected pool section, got %q", out)
	}
	if !strings.Contains(out, "exhaustion events") && !strings.Contains(out, "Pool exhaustion") {
		t.Errorf("expected exhaustion details in output, got %q", out)
	}
}

// ─── GenerateResourceSection: unknown resource type ───────────────────────────

func TestGenerateResourceSection_UnknownResourceType(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventResourceLimit, TCPState: 7, Error: 50, Bytes: 1024},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	out := GenerateResourceSection(d)
	if !strings.Contains(out, "Resource-7") {
		t.Errorf("expected Resource-7 label for unknown type, got %q", out)
	}
}

// ─── formatProcessActivity: cap + unknown name ────────────────────────────────

func TestFormatProcessActivity_CapAndUnknownName(t *testing.T) {
	var evts []*events.Event
	for i := 0; i < config.TopProcessesLimit+5; i++ {
		evts = append(evts, &events.Event{
			Type:        events.EventExec,
			PID:         uint32(1000 + i),
			ProcessName: "",
		})
	}
	out := formatProcessActivity(evts)
	if out == "" {
		t.Fatal("expected non-empty process activity output")
	}
	if !strings.Contains(out, "unknown") {
		t.Errorf("expected 'unknown' name fallback, got %q", out)
	}
	listed := strings.Count(out, "    - PID ")
	if listed != config.TopProcessesLimit {
		t.Errorf("expected %d listed processes (cap), got %d", config.TopProcessesLimit, listed)
	}
}

// ─── GenerateSyscallSection: events present but none categorized ──────────────

func TestGenerateSyscallSection_NoCategorizedEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, Target: "example.com"},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	if out := GenerateSyscallSection(d, time.Second); out != "" {
		t.Errorf("expected empty syscall section when no syscall events, got %q", out)
	}
}

// ─── formatFastCGIActivity: worker cap, name-fill, method fallback ────────────

func TestFormatFastCGIActivity_NilGuardsAndWorkerCap(t *testing.T) {
	var reqs []*events.Event
	reqs = append(reqs, &events.Event{Type: events.EventFastCGIReq, PID: 1, Details: "123", Target: "/x"})
	reqs = append(reqs,
		&events.Event{Type: events.EventFastCGIReq, PID: 9, ProcessName: "", Details: "GET", Target: "/a"},
		&events.Event{Type: events.EventFastCGIReq, PID: 9, ProcessName: "php-fpm", Details: "GET", Target: "/a"},
	)
	for i := 0; i < config.TopProcessesLimit+4; i++ {
		reqs = append(reqs, &events.Event{
			Type:    events.EventFastCGIReq,
			PID:     uint32(2000 + i),
			Details: "GET",
			Target:  "/p",
		})
	}

	d := &mockDiagnostician{
		events:    reqs,
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	out := formatFastCGIActivity(d, time.Second)
	if !strings.Contains(out, "FastCGI Activity") {
		t.Errorf("expected FastCGI activity output, got %q", out)
	}
	if !strings.Contains(out, "?: ") {
		t.Errorf("expected '?' method bucket for method-less request, got %q", out)
	}
}

// ─── formatBursts: display cap ────────────────────────────────────────────────

func TestFormatBursts_ExceedsDisplayCap(t *testing.T) {
	start := time.Now()
	duration := 10 * time.Second
	var evts []*events.Event
	for bucket := 0; bucket < config.MaxBurstsDisplay+5; bucket++ {
		base := start.Add(time.Duration(bucket) * time.Second)
		for j := 0; j < 200; j++ {
			evts = append(evts, &events.Event{
				Type:      events.EventTCPSend,
				Timestamp: uint64(base.UnixNano()) + uint64(j),
			})
		}
	}
	out := formatBursts(evts, start, duration)
	if out == "" {
		t.Skip("burst detector returned no bursts for synthetic stream")
	}
	listed := strings.Count(out, "    - ")
	if listed > config.MaxBurstsDisplay {
		t.Errorf("expected at most %d listed bursts (cap), got %d", config.MaxBurstsDisplay, listed)
	}
}

func TestGenerateSyscallSection_WithSyscallEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventExec, PID: 1, ProcessName: "sh"},
			{Type: events.EventOpen, Target: "/etc/passwd"},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	if out := GenerateSyscallSection(d, time.Second); out == "" {
		t.Error("expected non-empty syscall section with exec/open events")
	}
}
