package main

import (
	"os"
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

	if cmd.RunE == nil {
		t.Error("RunE is nil — operator subcommand is not wired")
	}
}

func TestNewOperatorCmd_FlagsMapCleanlyToOptions(t *testing.T) {
	cmd := newOperatorCmd()
	if err := cmd.Flags().Set("system-namespace", "custom-ns"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("leader-elect", "false"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("webhook-port", "10443"); err != nil {
		t.Fatal(err)
	}

	opts := &operatorOptions{}
	opts.systemNamespace = cmd.Flag("system-namespace").Value.String()
	opts.leaderElectNamespace = cmd.Flag("leader-elect-namespace").Value.String()
	opts.metricsAddr = cmd.Flag("metrics-addr").Value.String()
	opts.healthAddr = cmd.Flag("health-addr").Value.String()
	opts.webhookCertDir = cmd.Flag("webhook-cert-dir").Value.String()
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
}

func TestToOperatorOptions_EmptyLeaderNSFallsBackToSystemNS(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "")
	if err := os.Unsetenv("POD_NAMESPACE"); err != nil {
		t.Fatalf("unset POD_NAMESPACE: %v", err)
	}

	opts := &operatorOptions{
		systemNamespace:      "sys-ns",
		leaderElectNamespace: "",
	}
	got := toOperatorOptions(opts)
	if got.LeaderElectionNamespace != "sys-ns" {
		t.Errorf("LeaderElectionNamespace=%q, want sys-ns (fallback)", got.LeaderElectionNamespace)
	}
}

func TestToOperatorOptions_PodNamespaceEnvOverridesDefault(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "pod-actual-ns")

	opts := &operatorOptions{
		systemNamespace:      "sys-ns",
		leaderElectNamespace: "podtrace-system",
	}
	got := toOperatorOptions(opts)
	if got.LeaderElectionNamespace != "pod-actual-ns" {
		t.Errorf("LeaderElectionNamespace=%q, want pod-actual-ns (env override)", got.LeaderElectionNamespace)
	}
}

func TestToOperatorOptions_ExplicitLeaderNSWinsOverEnv(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "pod-actual-ns")

	opts := &operatorOptions{
		systemNamespace:      "sys-ns",
		leaderElectNamespace: "explicit-ns",
	}
	got := toOperatorOptions(opts)
	if got.LeaderElectionNamespace != "explicit-ns" {
		t.Errorf("LeaderElectionNamespace=%q, want explicit-ns", got.LeaderElectionNamespace)
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

func TestNewOperatorCmd_WebhookCertDirDefault(t *testing.T) {
	cmd := newOperatorCmd()
	v, _ := cmd.Flags().GetString("webhook-cert-dir")
	// Default empty — operator runs without the webhook server unless the
	// operator pod is given a cert directory (via cert-manager or similar).
	if v != "" {
		t.Errorf("webhook-cert-dir default=%q want empty", v)
	}
}
