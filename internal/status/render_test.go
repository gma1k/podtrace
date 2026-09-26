package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/profiling"
)

func fullReport() Report {
	since := t0.Add(-4 * time.Minute)
	errPct, p95 := 12.5, 180.0
	return Report{
		GeneratedAt:   t0,
		WindowSeconds: 10,
		Summary:       Summary{Agents: 2, AgentsHealthy: 1, Issues: 1, Workloads: 3},
		Agents: []AgentStatus{
			{Node: "n1", Pod: "podtrace-agent-a", State: StateOK, Workloads: 3},
			{Node: "n2", Pod: "podtrace-agent-b", State: StateDegraded, Reason: "btf_unavailable", Restarts: 2},
		},
		Issues: []Issue{{ID: "l7.error_rate", Severity: "warning", Namespace: "shop", Workload: "checkout",
			Pod: "checkout-1", Node: "n1", Since: &since, Message: "High error rate\x1b[31m red\x1b[0m"}},
		Workloads: []Workload{
			{Namespace: "shop", Workload: "checkout", RequestsPerSecond: 12.34, ErrorPercent: &errPct, P95Milliseconds: &p95, Issues: 1},
			{Namespace: "shop", Workload: "cart"},
		},
		Profile: &WorkloadHotFrames{Namespace: "shop", Workload: "checkout", Samples: 200, Nodes: 2, SchedulerFrames: 40,
			Frames: []HotFrame{{Frame: "main.price", Count: 80, Percent: 40}}},
		Warnings: []string{"something to fix"},
	}
}

func TestTheTableViewShowsEverySection(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderText(&buf, fullReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"rates over 10.0s",
		"1/2 agents healthy",
		"degraded (btf_unavailable)",
		"l7.error_rate", "shop/checkout", "4m", "High error rate\uFFFD[31m red\uFFFD[0m",
		"12.3", "12.5%", "180ms",
		"PROFILE shop/checkout · 200 samples on 2 node(s) · 40 Go scheduler frame hits hidden",
		"40.0%  main.price",
		"! something to fix",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("a control sequence from an Event message reached the terminal")
	}
}

func TestTheTableViewSaysWhenThereIsNothing(t *testing.T) {
	var buf bytes.Buffer
	_ = RenderText(&buf, Report{GeneratedAt: t0, Profile: &WorkloadHotFrames{Namespace: "shop", Workload: "idle"}})
	out := buf.String()
	for _, want := range []string{"No active issues.", "No application traffic observed in the window.", "No frames captured yet."} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "rates over") || strings.Contains(out, "WARNINGS") || strings.Contains(out, "scheduler") {
		t.Errorf("empty report printed sections it has no data for:\n%s", out)
	}
}

func TestAnIssueWithoutDetailShowsDashes(t *testing.T) {
	var buf bytes.Buffer
	r := Report{GeneratedAt: t0, Issues: []Issue{{ID: "x", Severity: "warning", Namespace: "a", Workload: "b"}}}
	_ = RenderText(&buf, r)
	line := strings.Split(buf.String(), "\n")
	var row string
	for _, l := range line {
		if strings.HasPrefix(l, "warning") {
			row = l
		}
	}
	if strings.Count(row, "-") < 3 {
		t.Errorf("row %q; a missing pod, start and message should read as -", row)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestAWriteFailureIsReturned(t *testing.T) {
	if err := RenderText(failingWriter{}, fullReport()); err == nil {
		t.Error("table: no error")
	}
	if err := RenderJSON(failingWriter{}, fullReport(), true); err == nil {
		t.Error("json: no error")
	}
}

func TestJSONRoundTripsAndIsOneLinePerReportWhenStreaming(t *testing.T) {
	var pretty, stream bytes.Buffer
	_ = RenderJSON(&pretty, fullReport(), true)
	_ = RenderJSON(&stream, fullReport(), false)

	var back Report
	if err := json.Unmarshal(pretty.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Summary.Issues != 1 || back.Workloads[0].P95Milliseconds == nil || *back.Workloads[0].P95Milliseconds != 180 {
		t.Errorf("round trip lost data: %+v", back)
	}
	if n := strings.Count(strings.TrimSpace(stream.String()), "\n"); n != 0 {
		t.Errorf("a streamed report spans %d lines; --watch -o json must stay one object per line", n+1)
	}
}

func TestAnEmptyReportEncodesEmptyListsNotNull(t *testing.T) {
	var buf bytes.Buffer
	_ = RenderJSON(&buf, Build(nil, nil, Options{}, t0), false)
	for _, key := range []string{`"agents":[]`, `"issues":[]`, `"workloads":[]`} {
		if !strings.Contains(buf.String(), key) {
			t.Errorf("JSON lacks %s: a script iterating the list would break on null\n%s", key, buf.String())
		}
	}
}

func TestLongTextIsCut(t *testing.T) {
	got := clean(strings.Repeat("é", 200), 10)
	if n := len([]rune(got)); n != 10 || !strings.HasSuffix(got, "…") {
		t.Errorf("clean = %q (%d runes)", got, n)
	}
	if clean("a\n\tb   c", 50) != "a b c" {
		t.Errorf("whitespace was not collapsed: %q", clean("a\n\tb   c", 50))
	}
}

func TestDurationsReadNaturally(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-time.Second:                "0s",
		400 * time.Microsecond:      "0.40ms",
		120 * time.Millisecond:      "120ms",
		4400 * time.Millisecond:     "4.4s",
		5 * time.Minute:             "5m",
		3*time.Hour + 5*time.Minute: "3h5m",
		72 * time.Hour:              "3d",
	} {
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestProfilesAreMergedRankedAndCut(t *testing.T) {
	p := []Profile{
		{Profiles: []profiling.WorkloadProfile{
			{Namespace: "shop", Workload: "checkout", Samples: 10, SchedulerFrames: 2,
				Frames: []profiling.FrameCount{{Frame: "b", Count: 3}, {Frame: "a", Count: 3}, {Frame: "c", Count: 1}}},
			{Namespace: "shop", Workload: "cart", Samples: 99},
		}},
		{Profiles: []profiling.WorkloadProfile{{Namespace: "billing", Workload: "checkout", Samples: 50}}},
	}
	got := MergeProfiles(p, "shop", "checkout", 2)
	if got == nil || got.Samples != 10 || got.Nodes != 1 || got.SchedulerFrames != 2 {
		t.Fatalf("merged = %+v", got)
	}
	if len(got.Frames) != 2 || got.Frames[0].Frame != "a" || got.Frames[1].Frame != "b" || got.Frames[0].Percent != 30 {
		t.Errorf("frames = %+v; ties sort by name, and --top cuts the list", got.Frames)
	}
	if MergeProfiles(p, "shop", "missing", 5) != nil {
		t.Error("a workload no node profiles returned a profile")
	}
	empty := MergeProfiles([]Profile{{Profiles: []profiling.WorkloadProfile{{Namespace: "a", Workload: "b",
		Frames: []profiling.FrameCount{{Frame: "f", Count: 1}}}}}}, "a", "b", 0)
	if empty.Frames[0].Percent != 0 {
		t.Errorf("a profile with no samples produced a share: %+v", empty.Frames)
	}
}
