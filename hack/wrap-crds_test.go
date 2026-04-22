package hack_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestWrapCRDs_Idempotent asserts hack/wrap-crds.sh can be re-run on a
// directory it has already processed without double-wrapping or
// duplicating the keep annotation guard. controller-gen is invoked by
// `make manifests` on every type change, and wrap-crds runs right after
// — so the script has to be idempotent.
//
// Strategy: copy a representative raw (unwrapped) CRD into a tempdir,
// run wrap-crds once and capture the output, then run it a second time
// and assert byte-for-byte equality.
func TestWrapCRDs_Idempotent(t *testing.T) {
	repoRoot := findRepoRoot(t)
	script := filepath.Join(repoRoot, "hack", "wrap-crds.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("wrap-crds.sh missing: %v", err)
	}

	// Pick one CRD and strip the existing Helm directives to simulate
	// fresh controller-gen output.
	srcPath := filepath.Join(repoRoot, "deploy", "charts", "podtrace", "templates", "crds", "podtrace.io_podtraces.yaml")
	raw, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read %s: %v", srcPath, err)
	}
	fresh := stripHelmDirectivesFromScript(raw)

	tmp := t.TempDir()
	target := filepath.Join(tmp, "podtrace.io_podtraces.yaml")
	if err := os.WriteFile(target, fresh, 0o644); err != nil {
		t.Fatalf("write tempfile: %v", err)
	}

	runScript := func() []byte {
		cmd := exec.Command("bash", script, tmp)
		var out, errBuf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errBuf
		if err := cmd.Run(); err != nil {
			t.Fatalf("wrap-crds.sh: %v\nstderr: %s", err, errBuf.String())
		}
		got, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read after wrap: %v", err)
		}
		return got
	}

	firstPass := runScript()
	secondPass := runScript()

	if !bytes.Equal(firstPass, secondPass) {
		t.Errorf("wrap-crds.sh is not idempotent:\nfirst pass (%d bytes):\n%s\n---\nsecond pass (%d bytes):\n%s",
			len(firstPass), firstPass, len(secondPass), secondPass)
	}

	// Sanity: a single wrapped file must contain exactly one keep-annotation
	// guard and exactly one install-toggle. Multiple hits would mean the
	// script appended duplicates on the second run.
	if c := bytes.Count(firstPass, []byte("helm.sh/resource-policy: keep")); c != 1 {
		t.Errorf("keep annotation count=%d, want 1", c)
	}
	if c := bytes.Count(firstPass, []byte("{{- if .Values.crds.install }}")); c != 1 {
		t.Errorf("install-toggle count=%d, want 1", c)
	}
}

// stripHelmDirectivesFromScript removes `{{- ... }}` lines from a YAML
// file so wrap-crds.sh sees "unwrapped" input. Mirrors the envtest
// helper's logic, duplicated here so the hack package has no
// dependency on api/v1alpha1_test.
func stripHelmDirectivesFromScript(in []byte) []byte {
	var out bytes.Buffer
	for _, line := range strings.Split(string(in), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "{{-") || strings.HasPrefix(trimmed, "{{") {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate repo root (go.mod) from %s", dir)
	return ""
}
