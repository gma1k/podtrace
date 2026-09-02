package metricsexporter

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var docMetricRe = regexp.MustCompile("`(podtrace_[a-z0-9_]+)`")

func snapshotNames(t *testing.T) map[string]struct{} {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "metric-surface.txt"))
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}

	names := map[string]struct{}{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, _, ok := strings.Cut(line, "{")
		if !ok {
			t.Fatalf("malformed snapshot line %q", line)
		}
		names[name] = struct{}{}
	}
	if len(names) == 0 {
		t.Fatal("snapshot is empty")
	}
	return names
}

func TestDocumentedMetricsMatchSnapshot(t *testing.T) {
	docPath := filepath.Join("..", "..", "docs", "metrics.md")
	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}

	documented := map[string]struct{}{}
	for _, m := range docMetricRe.FindAllStringSubmatch(string(raw), -1) {
		documented[m[1]] = struct{}{}
	}

	declared := snapshotNames(t)

	var undocumented, absent []string
	for name := range declared {
		if _, ok := documented[name]; !ok {
			undocumented = append(undocumented, name)
		}
	}
	for name := range documented {
		if _, ok := declared[name]; !ok {
			absent = append(absent, name)
		}
	}
	sort.Strings(undocumented)
	sort.Strings(absent)

	for _, name := range undocumented {
		t.Errorf("%s is exported but not documented in docs/metrics.md", name)
	}
	for _, name := range absent {
		t.Errorf("docs/metrics.md documents %s, which is not exported by any collector", name)
	}
}

func TestDocumentedLabelsMatchSnapshot(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "metric-surface.txt"))
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}

	labels := map[string][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, rest, ok := strings.Cut(line, "{")
		if !ok {
			t.Fatalf("malformed snapshot line %q", line)
		}
		var keys []string
		for _, k := range strings.Split(strings.TrimSuffix(rest, "}"), ",") {
			if k != "" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		labels[name] = keys
	}

	docPath := filepath.Join("..", "..", "docs", "metrics.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}

	blockRe := regexp.MustCompile("(?m)\\*\\*`(podtrace_[a-z0-9_]+)`\\*\\*[^\n]*\n((?:- [^\n]*\n)+)")
	labelLineRe := regexp.MustCompile(`- Labels?: (.+)`)

	checked := 0
	for _, block := range blockRe.FindAllStringSubmatch(string(doc), -1) {
		name, body := block[1], block[2]

		line := labelLineRe.FindStringSubmatch(body)
		if line == nil {
			continue
		}

		want, ok := labels[name]
		if !ok {
			continue
		}

		var got []string
		if strings.TrimSpace(line[1]) != "none" {
			got = docMetricLabelRe.FindAllString(line[1], -1)
			for i := range got {
				got[i] = strings.Trim(got[i], "`")
			}
			sort.Strings(got)
		}

		checked++
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: docs/metrics.md lists labels [%s], code declares [%s]",
				name, strings.Join(got, ","), strings.Join(want, ","))
		}
	}

	if checked == 0 {
		t.Fatal("no labelled metric blocks found in docs/metrics.md; the parser is broken")
	}
}

var docMetricLabelRe = regexp.MustCompile("`[a-z0-9_]+`")
