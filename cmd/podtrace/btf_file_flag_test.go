package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/kubernetes/nodespawn"
)

func keepBTFFilePath(t *testing.T, value string) {
	t.Helper()
	previous := config.BTFFilePath
	config.BTFFilePath = value
	t.Cleanup(func() { config.BTFFilePath = previous })
}

func TestValidateBTFFileFlag(t *testing.T) {
	for _, path := range []string{"", "/boot/vmlinux.btf"} {
		if err := validateBTFFileFlag(path); err != nil {
			t.Errorf("validateBTFFileFlag(%q) = %v, want nil", path, err)
		}
	}
	for _, path := range []string{"vmlinux.btf", "./btf/vmlinux", "../vmlinux"} {
		err := validateBTFFileFlag(path)
		if err == nil || !strings.Contains(err.Error(), "absolute path") {
			t.Errorf("validateBTFFileFlag(%q) = %v, want an absolute-path error", path, err)
		}
	}
}

func TestApplyLocalBTFFile_LocalRunUsesTheFlag(t *testing.T) {
	keepBTFFilePath(t, "/from/env/vmlinux")
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "")

	applyLocalBTFFile("/boot/vmlinux.btf")

	if config.BTFFilePath != "/boot/vmlinux.btf" {
		t.Fatalf("BTFFilePath = %q, want the --btf-file path over PODTRACE_BTF_FILE", config.BTFFilePath)
	}
}

func TestApplyLocalBTFFile_UnsetFlagKeepsEnvironment(t *testing.T) {
	keepBTFFilePath(t, "/from/env/vmlinux")
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "")

	applyLocalBTFFile("")

	if config.BTFFilePath != "/from/env/vmlinux" {
		t.Fatalf("BTFFilePath = %q, want PODTRACE_BTF_FILE kept", config.BTFFilePath)
	}
}

func TestApplyLocalBTFFile_SpawnPodKeepsMountedPath(t *testing.T) {
	keepBTFFilePath(t, "/etc/podtrace/btf/vmlinux.btf")
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "1")

	applyLocalBTFFile("/boot/vmlinux.btf")

	if config.BTFFilePath != "/etc/podtrace/btf/vmlinux.btf" {
		t.Fatalf("BTFFilePath = %q, want the mounted path, not the host path", config.BTFFilePath)
	}
}

func TestNewChildArgsBuilder_DoesNotForwardBTFFile(t *testing.T) {
	cmd := &cobra.Command{Use: "podtrace"}
	cmd.Flags().String("btf-file", "", "")
	cmd.Flags().String("filter", "", "")
	if err := cmd.Flags().Set("btf-file", "/boot/vmlinux.btf"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("filter", "dns"); err != nil {
		t.Fatal(err)
	}

	args := strings.Join(newChildArgsBuilder(cmd, false, nil)("node-1", []nodespawn.PodRef{
		{Namespace: "ns", Name: "p", ContainerID: "abc", ContainerName: "app"},
	}), " ")

	if strings.Contains(args, "btf-file") {
		t.Fatalf("spawn pod argv forwards the host BTF path: %s", args)
	}
	if !strings.Contains(args, "--filter=dns") {
		t.Fatalf("spawn pod argv lost an ordinary flag: %s", args)
	}
}

func TestRunPodtraceRejectsRelativeBTFFileBeforeTracing(t *testing.T) {
	saveSinkGlobals(t)
	useEmptyKubeconfig(t)
	previous := spawnBTFFile
	t.Cleanup(func() { spawnBTFFile = previous })
	spawnBTFFile = "vmlinux.btf"

	err := runPodtrace(&cobra.Command{}, []string{"x"})

	if err == nil || !strings.Contains(err.Error(), "--btf-file") {
		t.Fatalf("runPodtrace = %v, want the --btf-file refusal", err)
	}
}
