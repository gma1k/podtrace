package config

import (
	"runtime/debug"
	"testing"
)

func TestParseNonNegativeFloatAcceptsZeroAndRejectsTheRest(t *testing.T) {
	for in, want := range map[string]struct {
		v  float64
		ok bool
	}{
		"0":    {0, true},
		"2.5":  {2.5, true},
		"-0.1": {0, false},
		"abc":  {0, false},
		"":     {0, false},
	} {
		if v, ok := ParseNonNegativeFloat(in); v != want.v || ok != want.ok {
			t.Errorf("ParseNonNegativeFloat(%q) = %v, %v; want %v, %v", in, v, ok, want.v, want.ok)
		}
	}
}

func TestFloatEnvFallsBackOnAnInvalidValue(t *testing.T) {
	t.Setenv("PODTRACE_TEST_FLOAT", "")
	if got := getFloatEnvOrDefault("PODTRACE_TEST_FLOAT", 7); got != 7 {
		t.Errorf("unset: got %v, want the default 7", got)
	}
	t.Setenv("PODTRACE_TEST_FLOAT", "1.5")
	if got := getFloatEnvOrDefault("PODTRACE_TEST_FLOAT", 7); got != 1.5 {
		t.Errorf("valid: got %v, want 1.5", got)
	}
	t.Setenv("PODTRACE_TEST_FLOAT", "-3")
	if got := getFloatEnvOrDefault("PODTRACE_TEST_FLOAT", 7); got != 7 {
		t.Errorf("negative: got %v, want the default 7 rather than a setting no threshold can mean", got)
	}
}

func TestBlockingPrivateExporterRangesIsOptIn(t *testing.T) {
	t.Setenv("PODTRACE_EXPORTER_BLOCK_PRIVATE", "")
	if ExporterBlockPrivateRanges() {
		t.Error("private ranges were blocked without being asked; in-cluster collectors would be refused")
	}
	t.Setenv("PODTRACE_EXPORTER_BLOCK_PRIVATE", "true")
	if !ExporterBlockPrivateRanges() {
		t.Error("PODTRACE_EXPORTER_BLOCK_PRIVATE=true was ignored")
	}
}

func TestRevisionComesFromTheBuildInfo(t *testing.T) {
	if got := revisionFrom(nil, false); got != "" {
		t.Errorf("no build info: got %q", got)
	}
	info := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.time", Value: "2026-09-25"},
		{Key: "vcs.revision", Value: "9ede6ee1234567"},
	}}
	if got := revisionFrom(info, true); got != "9ede6ee" {
		t.Errorf("got %q, want the 7-character short revision", got)
	}
	short := &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc"}}}
	if got := revisionFrom(short, true); got != "" {
		t.Errorf("a revision shorter than 7 characters produced %q", got)
	}
}
