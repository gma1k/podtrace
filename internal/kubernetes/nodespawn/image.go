package nodespawn

import (
	"os"
	"strings"

	"github.com/podtrace/podtrace/internal/config"
)

// ResolveImageOptions feed ResolveImage.
type ResolveImageOptions struct {
	Override string
	Version  string
}

// ResolveImage returns the container reference to run on the target node and
// a flag indicating whether the caller should warn the user about a soft
// fallback.
func ResolveImage(opts ResolveImageOptions) (image string, warn bool) {
	if v := strings.TrimSpace(opts.Override); v != "" {
		return v, false
	}
	if v := strings.TrimSpace(os.Getenv("PODTRACE_IMAGE")); v != "" {
		return v, false
	}

	repo := strings.TrimSpace(config.Image)
	if repo == "" {
		repo = "ghcr.io/gma1k/podtrace"
	}

	if hasTagOrDigest(repo) {
		return repo, false
	}

	version := strings.TrimSpace(opts.Version)
	if version == "" {
		version = "latest"
	}
	if looksLikeDevBuild(version) {
		return repo + ":latest", true
	}
	return repo + ":" + version, false
}

// looksLikeDevBuild reports whether the linker-baked version string is one
// that's clearly not a published release tag — i.e. a registry pull would
// fail. Catches the common cases:
//   - "dev" or "dev-<sha>"        (Makefile fallback when git is absent)
//   - "v0.11.11-14-g<sha>-dirty"  (git describe on a dirty tree — never a tag)
//   - "v0.11.11-14-g<sha>"        (git describe past a tag — also never a tag)
//
// A clean release like "v0.11.12" is treated as a real tag and used verbatim.
func looksLikeDevBuild(version string) bool {
	if strings.HasPrefix(version, "dev") {
		return true
	}
	if strings.HasSuffix(version, "-dirty") {
		return true
	}
	if strings.Contains(version, "-g") {
		return true
	}
	return false
}

// hasTagOrDigest reports whether the given image reference already carries a
// tag (":tag") or a digest ("@sha256:...").
func hasTagOrDigest(ref string) bool {
	if strings.Contains(ref, "@") {
		return true
	}
	last := strings.LastIndex(ref, "/")
	if last < 0 {
		return strings.Contains(ref, ":")
	}
	return strings.Contains(ref[last:], ":")
}
