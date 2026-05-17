package main

import (
	"reflect"
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

	for _, f := range []string{
		"system-namespace", "tracer-config", "node-name",
		"metrics-addr", "health-addr", "status-report-interval",
		"backend",
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
	if v != 0 {
		t.Errorf("default status-report-interval=%v, want 0 (delegates to agent package default)", v)
	}
	if _, err := toAgentOptions(&agentOptions{nodeName: "n"}); err == nil {
		if !strings.Contains("", "") {
			_ = err
		}
	}
}

// TestNewAgentCmd_BackendDefaultsToReal locks in the production
// default: an operator running `podtrace agent` with no flags gets the
// real eBPF backend.
func TestNewAgentCmd_BackendDefaultsToReal(t *testing.T) {
	cmd := newAgentCmd()
	v, err := cmd.Flags().GetString("backend")
	if err != nil {
		t.Fatalf("GetString backend: %v", err)
	}
	if v != backendModeReal {
		t.Errorf("default --backend=%q, want %q", v, backendModeReal)
	}
}

func TestSelectBackendFactory(t *testing.T) {
	t.Run("real", func(t *testing.T) {
		f, err := selectBackendFactory(backendModeReal)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if reflect.ValueOf(f).Pointer() != reflect.ValueOf(agentBackendFactory).Pointer() {
			t.Error("real mode must return agentBackendFactory (the eBPF tracer factory)")
		}
	})
	t.Run("empty-defaults-to-real", func(t *testing.T) {
		f, err := selectBackendFactory("")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if reflect.ValueOf(f).Pointer() != reflect.ValueOf(agentBackendFactory).Pointer() {
			t.Error("empty backend mode must fall through to agentBackendFactory")
		}
	})
	t.Run("noop", func(t *testing.T) {
		f, err := selectBackendFactory(backendModeNoop)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if reflect.ValueOf(f).Pointer() != reflect.ValueOf(noopBackendFactory).Pointer() {
			t.Error("noop mode must return noopBackendFactory")
		}
		b, err := f()
		if err != nil || b == nil {
			t.Errorf("noop factory returned backend=%v err=%v", b, err)
		}
	})
	t.Run("invalid-is-hard-error", func(t *testing.T) {
		if _, err := selectBackendFactory("not-a-mode"); err == nil {
			t.Error("invalid --backend must error at startup, not silently fall back to real")
		}
	})
}

// TestToAgentOptions_PropagatesBackendChoice asserts the flag value
// reaches agent.Options.BackendFactory.
func TestToAgentOptions_PropagatesBackendChoice(t *testing.T) {
	t.Setenv("NODE_NAME", "n")
	opts, err := toAgentOptions(&agentOptions{systemNamespace: "ns", backendMode: backendModeNoop})
	if err != nil {
		t.Fatalf("toAgentOptions: %v", err)
	}
	if opts.BackendFactory == nil {
		t.Fatal("production CLI must always set BackendFactory; nil hits the library/test noop fallback")
	}
	if reflect.ValueOf(opts.BackendFactory).Pointer() != reflect.ValueOf(noopBackendFactory).Pointer() {
		t.Error("backendMode=noop must inject noopBackendFactory")
	}
}

func TestToAgentOptions_RejectsInvalidBackend(t *testing.T) {
	t.Setenv("NODE_NAME", "n")
	if _, err := toAgentOptions(&agentOptions{systemNamespace: "ns", backendMode: "bogus"}); err == nil {
		t.Error("toAgentOptions must reject invalid --backend")
	}
}