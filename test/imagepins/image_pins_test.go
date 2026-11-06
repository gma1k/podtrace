package imagepins

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const repoRoot = "../.."

var (
	imageField   = regexp.MustCompile(`(?:^|\s|-\s*)image:\s*["']?([^"'\s#]+)`)
	imageFlag    = regexp.MustCompile(`--image[= ]["']?([^"'\s]+)`)
	fromLine     = regexp.MustCompile(`^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)`)
	listedImage  = regexp.MustCompile(`^\s+([a-z0-9][a-z0-9./-]*:[A-Za-z0-9._-]+(?:@sha256:[a-f0-9]{64})?)\s*$`)
	digestPinned = regexp.MustCompile(`^[^@\s]+:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$`)
)

var skippedDirs = map[string]bool{".git": true, "vendor": true, "node_modules": true, "bin": true, "dist": true}

func ownOrTemplated(ref string) bool {
	for _, marker := range []string{"$", "{{", "<", "__VERSION__"} {
		if strings.Contains(ref, marker) {
			return true
		}
	}
	for _, own := range []string{"ghcr.io/gma1k/podtrace", "podtrace-", "your-registry/", "mirror.internal/", "10.5.0.1:5000/"} {
		if strings.HasPrefix(ref, own) {
			return true
		}
	}
	return false
}

func dockerfile(path string) bool {
	return strings.HasPrefix(filepath.Base(path), "Dockerfile")
}

func scanned(path string) bool {
	if dockerfile(path) {
		return true
	}
	switch filepath.Ext(path) {
	case ".yaml", ".yml", ".md", ".sh":
		return filepath.Base(path) != "CHANGELOG.md"
	}
	return false
}

type finding struct {
	path string
	line int
	ref  string
}

func imageReferences(t *testing.T) []finding {
	t.Helper()
	root, err := os.OpenRoot(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	var found []finding
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !scanned(path) {
			return nil
		}
		f, err := root.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		stages := map[string]bool{"scratch": true}
		inList := false
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for n := 1; sc.Scan(); n++ {
			line := sc.Text()
			var refs []string
			if dockerfile(path) {
				if m := fromLine.FindStringSubmatch(line); m != nil {
					if fields := strings.Fields(line); len(fields) >= 2 && strings.EqualFold(fields[len(fields)-2], "AS") {
						stages[fields[len(fields)-1]] = true
					}
					if !stages[m[1]] {
						refs = append(refs, m[1])
					}
				}
			} else {
				for _, m := range imageField.FindAllStringSubmatch(line, -1) {
					refs = append(refs, m[1])
				}
				for _, m := range imageFlag.FindAllStringSubmatch(line, -1) {
					refs = append(refs, m[1])
				}
				if strings.HasSuffix(strings.TrimSpace(line), "_IMAGES: >-") {
					inList = true
					continue
				}
				if inList {
					if m := listedImage.FindStringSubmatch(line); m != nil {
						refs = append(refs, m[1])
					} else {
						inList = false
					}
				}
			}
			for _, ref := range refs {
				if !ownOrTemplated(ref) {
					found = append(found, finding{path: path, line: n, ref: ref})
				}
			}
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestEveryThirdPartyImageIsPinnedToATagAndDigest(t *testing.T) {
	found := imageReferences(t)
	if len(found) == 0 {
		t.Fatal("no image references found; the scan is not reading the repository")
	}
	for _, f := range found {
		if !digestPinned.MatchString(f.ref) {
			t.Errorf("%s:%d: %q is not pinned as name:tag@sha256:<digest>; a tag alone can be "+
				"re-pushed, and a digest alone gives Renovate no version to update", f.path, f.line, f.ref)
		}
	}
}

func TestTheScanSeesEachKindOfReference(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range imageReferences(t) {
		switch {
		case dockerfile(f.path):
			seen["dockerfile"] = true
		case strings.HasSuffix(f.path, ".md"):
			seen["markdown"] = true
		case strings.Contains(f.path, ".github/workflows"):
			seen["workflow"] = true
		case strings.Contains(f.path, "test/chainsaw"):
			seen["chainsaw"] = true
		}
	}
	for _, kind := range []string{"dockerfile", "markdown", "workflow", "chainsaw"} {
		if !seen[kind] {
			t.Errorf("found no %s image references; the scan would pass without checking them", kind)
		}
	}
}

var natively = regexp.MustCompile(`(^|/)(Dockerfile[^/]*|(docker-)?compose[^/]*\.ya?ml)$|^deploy/charts/.+/(Chart\.yaml|templates/.+\.yaml)$`)

type renovateConfig struct {
	CustomManagers []struct {
		ManagerFilePatterns []string `json:"managerFilePatterns"`
		MatchStrings        []string `json:"matchStrings"`
	} `json:"customManagers"`
}

func renovateManagers(t *testing.T) (files []*regexp.Regexp, matches []*regexp.Regexp) {
	t.Helper()
	root, err := os.OpenRoot(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	raw, err := root.ReadFile(".github/renovate.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg renovateConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, m := range cfg.CustomManagers {
		for _, p := range m.ManagerFilePatterns {
			rx, err := regexp.Compile(strings.TrimSuffix(strings.TrimPrefix(p, "/"), "/"))
			if err != nil {
				t.Fatalf("renovate managerFilePattern %q does not compile: %v", p, err)
			}
			files = append(files, rx)
		}
		for _, s := range m.MatchStrings {
			rx, err := regexp.Compile(strings.ReplaceAll(s, "(?<", "(?P<"))
			if err != nil {
				t.Fatalf("renovate matchString %q does not compile: %v", s, err)
			}
			matches = append(matches, rx)
		}
	}
	return files, matches
}

func TestEveryPinnedImageIsTrackedByRenovate(t *testing.T) {
	filePatterns, matchStrings := renovateManagers(t)
	for _, f := range imageReferences(t) {
		rel := f.path
		if natively.MatchString(rel) {
			continue
		}
		fileTracked := false
		for _, rx := range filePatterns {
			if rx.MatchString(rel) {
				fileTracked = true
				break
			}
		}
		refTracked := false
		for _, rx := range matchStrings {
			if rx.MatchString(f.ref) {
				refTracked = true
				break
			}
		}
		if !fileTracked || !refTracked {
			t.Errorf("%s:%d: %q is pinned but no Renovate manager reads it (file matched: %v, reference matched: %v), "+
				"so its digest never moves", rel, f.line, f.ref, fileTracked, refTracked)
		}
	}
}
