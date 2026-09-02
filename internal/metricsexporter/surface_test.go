package metricsexporter

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

const surfaceUpdateEnv = "PODTRACE_UPDATE_METRIC_SURFACE"

var (
	fqNameRe    = regexp.MustCompile(`fqName: "([^"]*)"`)
	varLabelsRe = regexp.MustCompile(`variableLabels: \{([^}]*)\}`)
)

func renderMetricSurface(t *testing.T) string {
	t.Helper()

	ch := make(chan *prometheus.Desc, 256)
	go func() {
		defer close(ch)
		for _, c := range allCollectors() {
			c.Describe(ch)
		}
	}()

	lines := make([]string, 0, 64)
	for desc := range ch {
		raw := desc.String()

		name := fqNameRe.FindStringSubmatch(raw)
		if name == nil {
			t.Fatalf("could not parse fqName out of %q", raw)
		}

		var labels []string
		if got := varLabelsRe.FindStringSubmatch(raw); got != nil && got[1] != "" {
			labels = strings.Split(got[1], ",")
			for i := range labels {
				labels[i] = strings.TrimSpace(labels[i])
			}
			sort.Strings(labels)
		}

		lines = append(lines, fmt.Sprintf("%s{%s}", name[1], strings.Join(labels, ",")))
	}

	if len(lines) == 0 {
		t.Fatal("no metric descriptors collected; allCollectors() is empty or Describe is broken")
	}

	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func TestMetricSurfaceMatchesSnapshot(t *testing.T) {
	got := renderMetricSurface(t)
	path := filepath.Join("testdata", "metric-surface.txt")

	if os.Getenv(surfaceUpdateEnv) != "" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot: %v (regenerate with %s=1 go test ./internal/metricsexporter/)", err, surfaceUpdateEnv)
	}

	if got == string(raw) {
		return
	}

	added, removed := diffLines(strings.Split(strings.TrimRight(string(raw), "\n"), "\n"),
		strings.Split(strings.TrimRight(got, "\n"), "\n"))

	var b strings.Builder
	b.WriteString("the exported metric surface changed\n\n")
	for _, l := range removed {
		fmt.Fprintf(&b, "  - %s\n", l)
	}
	for _, l := range added {
		fmt.Fprintf(&b, "  + %s\n", l)
	}
	b.WriteString("\nMetric names and label keys are a compatibility surface; see the\n")
	b.WriteString("\"Metrics surface\" section of STABILITY.md. If this change is intended,\n")
	b.WriteString("record it in CHANGELOG.md and regenerate with:\n")
	fmt.Fprintf(&b, "  %s=1 go test ./internal/metricsexporter/\n", surfaceUpdateEnv)

	t.Error(b.String())
}

func diffLines(want, got []string) (added, removed []string) {
	inWant := make(map[string]struct{}, len(want))
	for _, l := range want {
		inWant[l] = struct{}{}
	}
	inGot := make(map[string]struct{}, len(got))
	for _, l := range got {
		inGot[l] = struct{}{}
	}

	for _, l := range got {
		if _, ok := inWant[l]; !ok {
			added = append(added, l)
		}
	}
	for _, l := range want {
		if _, ok := inGot[l]; !ok {
			removed = append(removed, l)
		}
	}
	return added, removed
}
