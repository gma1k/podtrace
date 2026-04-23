package main

import (
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

	// RunE must be wired; we cannot execute it in a unit test because it
	// starts a real manager that needs a kubeconfig. End-to-end coverage
	// lives in envtest (internal/operator/*_test.go) and the kind-cluster
	// smoke script under test/e2e/.
	if cmd.RunE == nil {
		t.Error("RunE is nil — operator subcommand is not wired")
	}
}

func TestNewOperatorCmd_FlagsMapCleanlyToOptions(t *testing.T) {
	cmd := newOperatorCmd()
	// Override a couple of flags to non-default values and confirm they
	// propagate through toOperatorOptions. Keeps the CLI↔library contract
	// honest without booting a manager.
	if err := cmd.Flags().Set("system-namespace", "custom-ns"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("leader-elect", "false"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("webhook-port", "10443"); err != nil {
		t.Fatal(err)
	}

	// The options struct is owned privately by newOperatorCmd's closure;
	// we re-derive it via the same translation helper the RunE uses.
	opts := &operatorOptions{}
	opts.systemNamespace = cmd.Flag("system-namespace").Value.String()
	opts.leaderElectNamespace = cmd.Flag("leader-elect-namespace").Value.String()
	opts.metricsAddr = cmd.Flag("metrics-addr").Value.String()
	opts.healthAddr = cmd.Flag("health-addr").Value.String()
	opts.webhookCertDir = cmd.Flag("webhook-cert-dir").Value.String()
	// bools/ints need typed getters
	opts.leaderElect, _ = cmd.Flags().GetBool("leader-elect")
	opts.webhookPort, _ = cmd.Flags().GetInt("webhook-port")

	runtimeOpts := toOperatorOptions(opts)
	if runtimeOpts.SystemNamespace != "custom-ns" {
		t.Errorf("SystemNamespace=%q want custom-ns", runtimeOpts.SystemNamespace)
	}
	if runtimeOpts.LeaderElection {
		t.Error("LeaderElection should be false after override")
	}
	if runtimeOpts.WebhookPort != 10443 {
		t.Errorf("WebhookPort=%d want 10443", runtimeOpts.WebhookPort)
	}
	// The toOperatorOptions return type is operator.Options by
	// declaration; no further runtime assertion needed.
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

func TestNewOperatorCmd_WebhookCertDirDefault(t *testing.T) {
	cmd := newOperatorCmd()
	v, _ := cmd.Flags().GetString("webhook-cert-dir")
	// Default empty — operator runs without the webhook server unless the
	// operator pod is given a cert directory (via cert-manager or similar).
	if v != "" {
		t.Errorf("webhook-cert-dir default=%q want empty", v)
	}
}
