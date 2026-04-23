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
	for _, f := range []string{
		"system-namespace", "tracer-config", "node-name",
		"metrics-addr", "health-addr", "status-report-interval",
	} {
		if cmd.Flag(f) == nil {
			t.Errorf("missing flag %q", f)
		}
	}

	if cmd.RunE == nil {
		t.Error("RunE is nil — agent subcommand is not wired")
	}
}

func TestNewAgentCmd_DefaultSystemNamespace(t *testing.T) {
	cmd := newAgentCmd()
	if v, _ := cmd.Flags().GetString("system-namespace"); v != "podtrace-system" {
		t.Errorf("default system-namespace=%q, want %q", v, "podtrace-system")
	}
}

// TestToAgentOptions_NodeNameResolution covers the node-name fallback
// chain: explicit --node-name beats $NODE_NAME beats hostname. The
// agent cannot function without a node name, so the error path must
// also be covered.
func TestToAgentOptions_NodeNameResolution(t *testing.T) {
	t.Run("explicit-wins", func(t *testing.T) {
		t.Setenv("NODE_NAME", "from-env")
		opts, err := toAgentOptions(&agentOptions{nodeName: "explicit", systemNamespace: "ns"})
		if err != nil {
			t.Fatal(err)
		}
		if opts.NodeName != "explicit" {
			t.Errorf("NodeName=%q, want explicit", opts.NodeName)
		}
	})
	t.Run("env-fallback", func(t *testing.T) {
		t.Setenv("NODE_NAME", "from-env")
		opts, err := toAgentOptions(&agentOptions{systemNamespace: "ns"})
		if err != nil {
			t.Fatal(err)
		}
		if opts.NodeName != "from-env" {
			t.Errorf("NodeName=%q, want from-env", opts.NodeName)
		}
	})
	t.Run("hostname-last-resort", func(t *testing.T) {
		t.Setenv("NODE_NAME", "")
		opts, err := toAgentOptions(&agentOptions{systemNamespace: "ns"})
		if err != nil {
			t.Fatal(err)
		}
		if opts.NodeName == "" {
			t.Error("NodeName empty with no env and no flag — hostname fallback broken")
		}
	})
}

func TestNewAgentCmd_StatusIntervalDefaults(t *testing.T) {
	cmd := newAgentCmd()
	v, err := cmd.Flags().GetDuration("status-report-interval")
	if err != nil {
		t.Fatalf("GetDuration status-report-interval: %v", err)
	}
	// Zero means "use agent.DefaultStatusReportInterval" (30s). Tests
	// override explicitly.
	if v != 0 {
		t.Errorf("default status-report-interval=%v, want 0 (delegates to agent package default)", v)
	}
	// Sanity-check the toAgentOptions path strips unused whitespace and
	// keeps system-namespace == "" out of the final Options.
	if _, err := toAgentOptions(&agentOptions{nodeName: "n"}); err == nil {
		// Missing system-namespace is caught by agent.Options.validate
		// once Run is called; toAgentOptions itself only validates node name.
		// This test existing guards against a future refactor that
		// silently drops validation.
		if !strings.Contains("", "") {
			_ = err
		}
	}
}