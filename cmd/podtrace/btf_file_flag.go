package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/kubernetes/nodespawn"
)

// validateBTFFileFlag refuses a --btf-file that is not an absolute path: a
// spawn pod mounts it as a hostPath, and a local trace must not resolve it
// against whatever directory the CLI happens to run in.
func validateBTFFileFlag(path string) error {
	if path == "" || filepath.IsAbs(path) {
		return nil
	}
	return fmt.Errorf("--btf-file %q must be an absolute path on the node", path)
}

// applyLocalBTFFile hands --btf-file to a trace that runs in this process:
// --local, an in-cluster run, or a selection that is not spawned. A spawn pod
// gets the file mounted instead and named by PODTRACE_BTF_FILE, so inside one
// the flag, which names the host path, is ignored.
func applyLocalBTFFile(path string) {
	if path == "" || os.Getenv(nodespawn.EnvNodeLocalSentinel) == "1" {
		return
	}
	config.BTFFilePath = path
}
