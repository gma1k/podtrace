package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/podtrace/podtrace/internal/diagnose"
	"github.com/podtrace/podtrace/internal/events"
)

func TestParseReportToSpec(t *testing.T) {
	cases := []struct {
		in                       string
		wantKind, wantNS, wantNm string
		wantErr                  bool
	}{
		{"configmap/prod/report", "configmap", "prod", "report", false},
		{"Secret/default/x", "secret", "default", "x", false},
		{"bad", "", "", "", true},
		{"a/b", "", "", "", true},
		{"/b/c", "", "", "", true},
		{"a//c", "", "", "", true},
		{"a/b/", "", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			k, ns, n, err := parseReportToSpec(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if err == nil && (k != tc.wantKind || ns != tc.wantNS || n != tc.wantNm) {
				t.Errorf("got (%q,%q,%q) want (%q,%q,%q)", k, ns, n, tc.wantKind, tc.wantNS, tc.wantNm)
			}
		})
	}
}

func TestComputeSessionSummary_Categorises(t *testing.T) {
	d := diagnose.NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS})
	d.AddEvent(&events.Event{Type: events.EventConnect})
	d.AddEvent(&events.Event{Type: events.EventTCPSend})
	d.AddEvent(&events.Event{Type: events.EventWrite, Error: 1})
	d.AddEvent(&events.Event{Type: events.EventExec})
	d.AddEvent(&events.Event{Type: events.EventSchedSwitch})
	d.Finish()

	s := computeSessionSummary(d, "node-a")
	if s.TotalEvents != 6 {
		t.Errorf("total=%d want 6", s.TotalEvents)
	}
	if s.DNSEvents != 1 {
		t.Errorf("dns=%d", s.DNSEvents)
	}
	if s.NetEvents != 2 {
		t.Errorf("net=%d", s.NetEvents)
	}
	if s.FSEvents != 1 {
		t.Errorf("fs=%d", s.FSEvents)
	}
	if s.ProcEvents != 1 {
		t.Errorf("proc=%d", s.ProcEvents)
	}
	if s.CPUEvents != 1 {
		t.Errorf("cpu=%d", s.CPUEvents)
	}
	if s.ErrorsDetected != 1 {
		t.Errorf("errors=%d", s.ErrorsDetected)
	}
	if s.Node != "node-a" {
		t.Errorf("node=%q", s.Node)
	}
}

func TestWriteTerminationMessage_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "termination-log")
	summary := SessionSummary{TotalEvents: 10, DNSEvents: 3, Node: "n"}
	if err := writeTerminationMessage(path, summary); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got SessionSummary
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.TotalEvents != 10 || got.Node != "n" {
		t.Errorf("round-trip: %+v", got)
	}
}

func TestWriteTerminationMessage_RejectsOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "termination-log")
	big := make([]byte, 5000)
	for i := range big {
		big[i] = 'x'
	}
	err := writeTerminationMessage(path, SessionSummary{Node: string(big)})
	if err == nil {
		t.Fatal("expected oversize error")
	}
}

func TestUpsertReportConfigMap_CreateThenUpdate(t *testing.T) {
	client := fake.NewSimpleClientset()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := upsertReportConfigMap(ctx, client, "ns", "rpt", "hello"); err != nil {
		t.Fatal(err)
	}
	cm, err := client.CoreV1().ConfigMaps("ns").Get(ctx, "rpt", metav1.GetOptions{})
	if err != nil || cm.Data["report.txt"] != "hello" {
		t.Fatalf("create wrong: %v %+v", err, cm)
	}

	if err := upsertReportConfigMap(ctx, client, "ns", "rpt", "updated"); err != nil {
		t.Fatal(err)
	}
	cm2, err := client.CoreV1().ConfigMaps("ns").Get(ctx, "rpt", metav1.GetOptions{})
	if err != nil || cm2.Data["report.txt"] != "updated" {
		t.Fatalf("update wrong: %v %+v", err, cm2)
	}
}

func TestUpsertReportSecret_CreateThenUpdate(t *testing.T) {
	client := fake.NewSimpleClientset()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := upsertReportSecret(ctx, client, "ns", "rpt", "sensitive"); err != nil {
		t.Fatal(err)
	}
	sec, err := client.CoreV1().Secrets("ns").Get(ctx, "rpt", metav1.GetOptions{})
	if err != nil || string(sec.Data["report.txt"]) != "sensitive" {
		t.Fatalf("create wrong: %v %+v", err, sec)
	}

	if err := upsertReportSecret(ctx, client, "ns", "rpt", "updated"); err != nil {
		t.Fatal(err)
	}
	sec2, err := client.CoreV1().Secrets("ns").Get(ctx, "rpt", metav1.GetOptions{})
	if err != nil || string(sec2.Data["report.txt"]) != "updated" {
		t.Fatalf("update wrong: %v %+v", err, sec2)
	}
}

func TestUpsertReportConfigMap_PreservesExistingKeys(t *testing.T) {
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "rpt", Namespace: "ns"},
		Data:       map[string]string{"other": "keep me"},
	}
	client := fake.NewSimpleClientset(existing)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := upsertReportConfigMap(ctx, client, "ns", "rpt", "new report"); err != nil {
		t.Fatal(err)
	}
	cm, _ := client.CoreV1().ConfigMaps("ns").Get(ctx, "rpt", metav1.GetOptions{})
	if cm.Data["other"] != "keep me" {
		t.Errorf("lost unrelated key: %+v", cm.Data)
	}
	if cm.Data["report.txt"] != "new report" {
		t.Errorf("report.txt: %q", cm.Data["report.txt"])
	}
}

func TestEmitSessionArtifacts_AllThreeSinks(t *testing.T) {
	defer func() {
		summaryFile = ""
		terminationMessagePath = ""
		reportTo = ""
	}()
	dir := t.TempDir()
	summaryFile = filepath.Join(dir, "summary.json")
	terminationMessagePath = filepath.Join(dir, "term.json")
	reportTo = ""

	summary := SessionSummary{TotalEvents: 42, DNSEvents: 10}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := emitSessionArtifacts(ctx, summary, "report body"); err != nil {
		t.Fatalf("emit: %v", err)
	}

	if raw, err := os.ReadFile(summaryFile); err != nil {
		t.Errorf("read summary: %v", err)
	} else {
		var s SessionSummary
		if err := json.Unmarshal(raw, &s); err != nil || s.TotalEvents != 42 {
			t.Errorf("summary parse: %v %+v", err, s)
		}
	}
	if _, err := os.Stat(terminationMessagePath); err != nil {
		t.Errorf("termination message missing: %v", err)
	}
}

func TestEmitSessionArtifacts_NoSinks_IsNoop(t *testing.T) {
	defer func() {
		summaryFile = ""
		terminationMessagePath = ""
		reportTo = ""
	}()
	summaryFile = ""
	terminationMessagePath = ""
	reportTo = ""

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := emitSessionArtifacts(ctx, SessionSummary{}, ""); err != nil {
		t.Fatalf("no-sinks emit should be no-op: %v", err)
	}
}