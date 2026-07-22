package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

func TestEmitSessionArtifacts_AggregatesSinkErrors(t *testing.T) {
	saveSinkGlobals(t)
	t.Setenv(config.EnvArtifactBaseDir, "")

	dir := t.TempDir()
	summaryFile = filepath.Join(dir, "missing-summary-dir", "summary.json")
	terminationMessagePath = filepath.Join(dir, "missing-term-dir", "term.json")
	reportTo = ""

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := emitSessionArtifacts(ctx, SessionSummary{TotalEvents: 1}, "report body")
	if err == nil {
		t.Fatal("expected an aggregated error when both file sinks fail")
	}
	if !strings.Contains(err.Error(), "summary-file:") {
		t.Errorf("expected summary-file failure in aggregated error, got %v", err)
	}
	if !strings.Contains(err.Error(), "termination-message:") {
		t.Errorf("expected termination-message failure in aggregated error, got %v", err)
	}
}
