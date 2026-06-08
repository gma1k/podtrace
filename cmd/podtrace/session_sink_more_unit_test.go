package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/diagnose"
)

// saveSinkGlobals snapshots the package-level sink destination globals
// and restores them on cleanup so tests do not leak into one another.
func saveSinkGlobals(t *testing.T) {
	t.Helper()
	origSummary := summaryFile
	origTermination := terminationMessagePath
	origReportTo := reportTo
	t.Cleanup(func() {
		summaryFile = origSummary
		terminationMessagePath = origTermination
		reportTo = origReportTo
	})
}

func TestFinalizeDiagnoseOutputs_AllEmptyIsNoOp(t *testing.T) {
	saveSinkGlobals(t)
	summaryFile = ""
	terminationMessagePath = ""
	reportTo = ""

	d := diagnose.NewDiagnostician()
	finalizeDiagnoseOutputs(context.Background(), "report text", d)
}

func TestFinalizeDiagnoseOutputs_WritesSummaryFile(t *testing.T) {
	saveSinkGlobals(t)
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")

	summaryFile = summaryPath
	terminationMessagePath = ""
	reportTo = ""

	t.Setenv("NODE_NAME", "node-under-test")

	d := diagnose.NewDiagnostician()
	finalizeDiagnoseOutputs(context.Background(), "report text", d)

	raw, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("summary file not written: %v", err)
	}
	var got SessionSummary
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("summary file is not valid JSON: %v", err)
	}
	if got.Node != "node-under-test" {
		t.Errorf("summary.Node = %q, want %q", got.Node, "node-under-test")
	}
	if got.TotalEvents != 0 {
		t.Errorf("summary.TotalEvents = %d, want 0 for an empty diagnostician", got.TotalEvents)
	}
}

func TestFinalizeDiagnoseOutputs_WritesTerminationMessage(t *testing.T) {
	saveSinkGlobals(t)
	dir := t.TempDir()
	termPath := filepath.Join(dir, "termination.json")

	summaryFile = ""
	terminationMessagePath = termPath
	reportTo = ""

	d := diagnose.NewDiagnostician()
	finalizeDiagnoseOutputs(context.Background(), "report text", d)

	raw, err := os.ReadFile(termPath)
	if err != nil {
		t.Fatalf("termination message not written: %v", err)
	}
	var got SessionSummary
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("termination message is not valid JSON: %v", err)
	}
}

func TestFinalizeDiagnoseOutputs_LocalAndObjectStoreSink(t *testing.T) {
	saveSinkGlobals(t)
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	termPath := filepath.Join(dir, "termination.json")

	summaryFile = summaryPath
	terminationMessagePath = termPath
	reportTo = "s3://bucket/key"

	d := diagnose.NewDiagnostician()
	finalizeDiagnoseOutputs(context.Background(), "report text", d)

	if _, err := os.Stat(summaryPath); err != nil {
		t.Errorf("summary file missing: %v", err)
	}
	if _, err := os.Stat(termPath); err != nil {
		t.Errorf("termination message missing: %v", err)
	}
}
