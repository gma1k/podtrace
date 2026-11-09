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
	Extends        []string  `json:"extends"`
	IgnorePaths    *[]string `json:"ignorePaths"`
	CustomManagers []struct {
		ManagerFilePatterns []string `json:"managerFilePatterns"`
		MatchStrings        []string `json:"matchStrings"`
	} `json:"customManagers"`
}

var recommendedIgnorePaths = []string{
	"**/node_modules/**",
	"**/bower_components/**",
	"**/vendor/**",
	"**/examples/**",
	"**/__tests__/**",
	"**/test/**",
	"**/tests/**",
	"**/__fixtures__/**",
}

func loadRenovateConfig(t *testing.T) renovateConfig {
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
	return cfg
}

func effectiveIgnorePaths(cfg renovateConfig) []string {
	if cfg.IgnorePaths != nil {
		return *cfg.IgnorePaths
	}
	for _, preset := range cfg.Extends {
		if preset == "config:recommended" || preset == ":ignoreModulesAndTests" {
			return recommendedIgnorePaths
		}
	}
	return nil
}

func globToRegexp(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		switch {
		case strings.HasPrefix(glob[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(glob[i:], "/**") && i+3 == len(glob):
			b.WriteString("(?:/.*)?")
			i += 2
		case glob[i] == '*':
			b.WriteString("[^/]*")
		case glob[i] == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(glob[i])))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func renovateIgnores(cfg renovateConfig) func(string) bool {
	var globs []*regexp.Regexp
	for _, g := range effectiveIgnorePaths(cfg) {
		globs = append(globs, globToRegexp(g))
	}
	return func(path string) bool {
		for _, rx := range globs {
			if rx.MatchString(path) {
				return true
			}
		}
		return false
	}
}

func renovateManagers(t *testing.T) (files []*regexp.Regexp, matches []*regexp.Regexp) {
	t.Helper()
	cfg := loadRenovateConfig(t)
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
	ignored := renovateIgnores(loadRenovateConfig(t))
	for _, f := range imageReferences(t) {
		rel := f.path
		if ignored(rel) {
			t.Errorf("%s:%d: %q is pinned in a path Renovate's ignorePaths skip, so no manager ever reads it", rel, f.line, f.ref)
			continue
		}
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

func TestRenovateScansEveryDependencyManifest(t *testing.T) {
	ignored := renovateIgnores(loadRenovateConfig(t))
	manifest := regexp.MustCompile(`(^|/)(go\.mod|Dockerfile[^/]*|requirements[^/]*\.txt|Chart\.yaml)$`)
	root, err := os.OpenRoot(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	checked := 0
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
		if !manifest.MatchString(path) {
			return nil
		}
		checked++
		if ignored(path) {
			t.Errorf("%s is a dependency manifest in a path Renovate's ignorePaths skip; its dependencies never get update PRs", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("found no dependency manifests; the scan would pass without checking any")
	}
}

func TestRecommendedPresetIgnoresTestPathsUnlessOverridden(t *testing.T) {
	recommended := renovateConfig{Extends: []string{"config:recommended"}}
	if !renovateIgnores(recommended)("test/chainsaw/tests/x/seaweedfs.yaml") {
		t.Error("config:recommended without ignorePaths must be modelled as skipping test/")
	}
	if !renovateIgnores(recommended)("examples/podtrace.yaml") {
		t.Error("config:recommended without ignorePaths must be modelled as skipping examples/")
	}
	override := []string{"**/vendor/**"}
	overridden := renovateConfig{Extends: []string{"config:recommended"}, IgnorePaths: &override}
	if renovateIgnores(overridden)("test/pool-test/go.mod") {
		t.Error("an explicit ignorePaths replaces the preset's list")
	}
	if !renovateIgnores(overridden)("vendor/x/go.mod") || !renovateIgnores(overridden)("a/vendor/go.mod") {
		t.Error("**/vendor/** must match vendor at any depth")
	}
	if renovateIgnores(renovateConfig{})("test/x.yaml") {
		t.Error("a config without presets or ignorePaths ignores nothing")
	}
	if !globToRegexp("docs/*.md").MatchString("docs/a.md") || globToRegexp("docs/*.md").MatchString("docs/x/a.md") {
		t.Error("a single * must not cross a directory")
	}
	if !globToRegexp("a?c").MatchString("abc") {
		t.Error("? must match one character")
	}
}
