package main

import (
	"strings"
	"testing"
)

func TestNewOperatorCmd_Metadata(t *testing.T) {
	cmd := newOperatorCmd()
	if cmd == nil {
		t.Fatal("newOperatorCmd returned nil")
	}
	if cmd.Use != "operator" {
		t.Errorf("Use=%q, want %q", cmd.Use, "operator")
	}
	if cmd.Short == "" {
		t.Error("Short is empty")
	}

	for _, f := range []string{"system-namespace", "metrics-addr", "health-addr", "leader-elect", "leader-elect-namespace", "webhook-port", "webhook-cert-dir"} {
		if cmd.Flag(f) == nil {
			t.Errorf("missing flag %q", f)
		}
	}
}

func TestNewOperatorCmd_NotImplemented(t *testing.T) {
	cmd := newOperatorCmd()
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error from operator command")
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Errorf("error does not indicate unavailability: %q", err.Error())
	}
}

func TestNewOperatorCmd_LeaderElectDefault(t *testing.T) {
	cmd := newOperatorCmd()
	v, err := cmd.Flags().GetBool("leader-elect")
	if err != nil {
		t.Fatalf("GetBool leader-elect: %v", err)
	}
	if !v {
		t.Error("leader-elect default should be true for HA correctness")
	}
}

func TestNewOperatorCmd_WebhookPortDefault(t *testing.T) {
	cmd := newOperatorCmd()
	v, err := cmd.Flags().GetInt("webhook-port")
	if err != nil {
		t.Fatalf("GetInt webhook-port: %v", err)
	}
	// 9443 is the kubebuilder convention and matches the validating-webhook
	// Helm template's assumed service port.
	if v != 9443 {
		t.Errorf("webhook-port default=%d, want 9443", v)
	}
}
