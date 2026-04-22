package main

import (
	"strings"
	"testing"
)

func TestNewAgentCmd_Metadata(t *testing.T) {
	cmd := newAgentCmd()
	if cmd == nil {
		t.Fatal("newAgentCmd returned nil")
	}
	if cmd.Use != "agent" {
		t.Errorf("Use=%q, want %q", cmd.Use, "agent")
	}
	if cmd.Short == "" {
		t.Error("Short is empty")
	}
	if cmd.Long == "" {
		t.Error("Long is empty")
	}

	// If any of these flags disappear without a migration, the DaemonSet
	// template breaks silently. Keep them asserted.
	for _, f := range []string{"system-namespace", "tracer-config", "node-name", "metrics-addr", "health-addr"} {
		if cmd.Flag(f) == nil {
			t.Errorf("missing flag %q", f)
		}
	}
}

func TestNewAgentCmd_NotImplemented(t *testing.T) {
	cmd := newAgentCmd()
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error from agent command")
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Errorf("error does not indicate unavailability: %q", err.Error())
	}
}

func TestNewAgentCmd_DefaultSystemNamespace(t *testing.T) {
	cmd := newAgentCmd()
	if v, _ := cmd.Flags().GetString("system-namespace"); v != "podtrace-system" {
		t.Errorf("default system-namespace=%q, want %q", v, "podtrace-system")
	}
}
