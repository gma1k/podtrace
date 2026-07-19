package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/hostfs"
)

func TestWriteArtifactFile_JailGatedByEnv(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(t.TempDir(), "elsewhere.txt")

	t.Setenv(config.EnvArtifactBaseDir, "")
	if err := writeArtifactFile(outside, []byte("x"), 0o600); err != nil {
		t.Errorf("unconstrained write failed: %v", err)
	}

	t.Setenv(config.EnvArtifactBaseDir, base)
	inside := filepath.Join(base, "summary.json")
	if err := writeArtifactFile(inside, []byte("x"), 0o600); err != nil {
		t.Errorf("in-base write failed: %v", err)
	}
	if got, err := os.ReadFile(inside); err != nil || string(got) != "x" {
		t.Errorf("in-base file not written: got=%q err=%v", got, err)
	}
	if err := writeArtifactFile(outside, []byte("x"), 0o600); !errors.Is(err, hostfs.ErrOutsideBase) {
		t.Errorf("out-of-base write: got %v, want ErrOutsideBase", err)
	}

	if err := writeArtifactFile(k8sTerminationLog, []byte("x"), 0o600); errors.Is(err, hostfs.ErrOutsideBase) {
		t.Errorf("termination-log must be exempt from the base jail, got %v", err)
	}
}
