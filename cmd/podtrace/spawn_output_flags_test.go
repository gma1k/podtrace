package main

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/kubernetes/nodespawn"
)

func outputFlagsCmd(t *testing.T, set map[string]string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	for _, name := range []string{"summary-file", "termination-message-path", "exporter-from-file", "report-to"} {
		cmd.Flags().String(name, "", "")
	}
	for name, value := range set {
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	return cmd
}

func TestCheckSpawnOutputFlagsRefusesPodLocalFiles(t *testing.T) {
	for _, name := range []string{"summary-file", "termination-message-path", "exporter-from-file"} {
		t.Run(name, func(t *testing.T) {
			err := checkSpawnOutputFlags(outputFlagsCmd(t, map[string]string{name: "/tmp/x"}), "reporter")
			if err == nil || !strings.Contains(err.Error(), "--"+name) || !strings.Contains(err.Error(), "--local") {
				t.Errorf("checkSpawnOutputFlags(--%s) = %v, want a refusal naming the flag and --local", name, err)
			}
		})
	}
}

func TestCheckSpawnOutputFlagsKeepsReportTo(t *testing.T) {
	cmd := outputFlagsCmd(t, map[string]string{"report-to": "configmap/ns/name"})
	for _, sa := range []string{"", "reporter"} {
		if err := checkSpawnOutputFlags(cmd, sa); err != nil {
			t.Errorf("--report-to with service account %q refused: %v", sa, err)
		}
	}
	if err := checkSpawnOutputFlags(outputFlagsCmd(t, nil), ""); err != nil {
		t.Errorf("no output flags refused: %v", err)
	}
}

func TestMaybeSpawnOnNodeRefusesSummaryFileBeforeSpawning(t *testing.T) {
	saveSpawnGlobals(t)
	saveNodespawnGlobals(t)
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "")
	t.Setenv("PODTRACE_SPAWN_NAMESPACE", "")
	localMode = false
	spawnImage = "ghcr.io/gma1k/podtrace:test"

	handled, err := maybeSpawnOnNode(context.Background(), nil, outputFlagsCmd(t, map[string]string{"summary-file": "out.json"}),
		clusterResolver{}, pkgkube.TargetSelection{AllInNamespace: true, Namespaces: []string{"default"}})

	if !handled || err == nil || !strings.Contains(err.Error(), "--summary-file") {
		t.Fatalf("maybeSpawnOnNode = (%v, %v), want the summary-file refusal", handled, err)
	}
}
