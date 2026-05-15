package operator

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestScheduledSessionName_Idempotent(t *testing.T) {
	t1 := time.Date(2026, 5, 15, 12, 30, 0, 0, time.UTC)
	a := scheduledSessionName("nightly", t1)
	b := scheduledSessionName("nightly", t1)
	if a != b {
		t.Fatalf("scheduledSessionName not deterministic: %q != %q", a, b)
	}
	t2 := t1.Add(time.Minute)
	if a == scheduledSessionName("nightly", t2) {
		t.Fatalf("scheduledSessionName collided across distinct run times")
	}
}

func TestScheduledSessionName_LengthBounded(t *testing.T) {
	long := strings.Repeat("x", 70)
	got := scheduledSessionName(long, time.Now())
	if len(got) > 63 {
		t.Fatalf("scheduledSessionName overflowed: %d > 63 (%q)", len(got), got)
	}
}

func TestClassifySessions(t *testing.T) {
	mk := func(name string, state podtracev1alpha1.SessionState) podtracev1alpha1.PodTraceSession {
		return podtracev1alpha1.PodTraceSession{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Status:     podtracev1alpha1.PodTraceSessionStatus{State: state},
		}
	}
	in := []podtracev1alpha1.PodTraceSession{
		mk("running", podtracev1alpha1.SessionStateRunning),
		mk("pending", podtracev1alpha1.SessionStatePending),
		mk("complete", podtracev1alpha1.SessionStateCompleted),
		mk("failed", podtracev1alpha1.SessionStateFailed),
		mk("blank", ""),
	}
	a, s, f := classifySessions(in)
	if len(a) != 3 {
		t.Fatalf("active: got %d, want 3 (running+pending+blank)", len(a))
	}
	if len(s) != 1 || s[0].Name != "complete" {
		t.Fatalf("succeeded: %+v", s)
	}
	if len(f) != 1 || f[0].Name != "failed" {
		t.Fatalf("failed: %+v", f)
	}
}

func TestMostRecentSuccess(t *testing.T) {
	t1 := metav1.NewTime(time.Now().Add(-time.Hour))
	t2 := metav1.NewTime(time.Now())
	in := []podtracev1alpha1.PodTraceSession{
		{Status: podtracev1alpha1.PodTraceSessionStatus{CompletionTime: &t1}},
		{Status: podtracev1alpha1.PodTraceSessionStatus{CompletionTime: nil}},
		{Status: podtracev1alpha1.PodTraceSessionStatus{CompletionTime: &t2}},
	}
	got := mostRecentSuccess(in)
	if got == nil || !got.Equal(&t2) {
		t.Fatalf("got %v, want %v", got, t2)
	}
}

func TestSortByCompletion_OldestFirst(t *testing.T) {
	oldT := metav1.NewTime(time.Now().Add(-2 * time.Hour))
	midT := metav1.NewTime(time.Now().Add(-time.Hour))
	newT := metav1.NewTime(time.Now())
	in := []podtracev1alpha1.PodTraceSession{
		{ObjectMeta: metav1.ObjectMeta{Name: "new"}, Status: podtracev1alpha1.PodTraceSessionStatus{CompletionTime: &newT}},
		{ObjectMeta: metav1.ObjectMeta{Name: "old"}, Status: podtracev1alpha1.PodTraceSessionStatus{CompletionTime: &oldT}},
		{ObjectMeta: metav1.ObjectMeta{Name: "mid"}, Status: podtracev1alpha1.PodTraceSessionStatus{CompletionTime: &midT}},
	}
	sortByCompletion(in)
	if in[0].Name != "old" || in[1].Name != "mid" || in[2].Name != "new" {
		t.Fatalf("wrong order: %v", []string{in[0].Name, in[1].Name, in[2].Name})
	}
}

func TestRequeueAfter_Clamps(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name   string
		run    time.Time
		expect time.Duration
	}{
		{"past", now.Add(-time.Hour), scheduleResyncFloor},
		{"close", now.Add(time.Second), scheduleResyncFloor},
		{"mid", now.Add(20 * time.Second), 20 * time.Second},
		{"far", now.Add(time.Hour), scheduleResyncCeiling},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := requeueAfter(tc.run, now)
			if got != tc.expect {
				t.Fatalf("got %s, want %s", got, tc.expect)
			}
		})
	}
}

func TestParseSchedule_FiveAndSixField(t *testing.T) {
	cases := []string{
		"*/5 * * * *",
		"0 */5 * * * *", // 6-field with seconds
		"@hourly",
		"@every 5m",
	}
	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			if _, err := podtracev1alpha1.ParseSchedule(expr); err != nil {
				t.Fatalf("expected %q to parse: %v", expr, err)
			}
		})
	}
}

func TestParseSchedule_RejectsInvalid(t *testing.T) {
	for _, bad := range []string{"", "not-a-cron", "99 * * * *"} {
		t.Run(bad, func(t *testing.T) {
			if _, err := podtracev1alpha1.ParseSchedule(bad); err == nil {
				t.Fatalf("expected %q to fail to parse", bad)
			}
		})
	}
}