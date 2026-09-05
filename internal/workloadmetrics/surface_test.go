package workloadmetrics

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

func renderSurface(t *testing.T) string {
	t.Helper()

	ch := make(chan *prometheus.Desc, 256)
	go func() {
		defer close(ch)
		for _, c := range newCollectors(Options{NativeHistograms: true}).all() {
			c.Describe(ch)
		}
		for _, c := range newSemconvCollectors(true, defaultAttributeCardinality).all() {
			c.Describe(ch)
		}
		for _, c := range newEdgeCollectors(true, defaultAttributeCardinality).all() {
			c.Describe(ch)
		}
	}()

	lines := make([]string, 0, 32)
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
		t.Fatal("no descriptors collected; newCollectors().all() is empty or Describe is broken")
	}

	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func TestSurfaceMatchesSnapshot(t *testing.T) {
	got := renderSurface(t)
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
		t.Fatalf("read snapshot: %v (regenerate with %s=1 go test ./internal/workloadmetrics/)", err, surfaceUpdateEnv)
	}

	if got == string(raw) {
		return
	}

	want := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	have := strings.Split(strings.TrimRight(got, "\n"), "\n")

	inWant := map[string]struct{}{}
	for _, l := range want {
		inWant[l] = struct{}{}
	}
	inHave := map[string]struct{}{}
	for _, l := range have {
		inHave[l] = struct{}{}
	}

	var b strings.Builder
	b.WriteString("the continuous metric surface changed\n\n")
	for _, l := range want {
		if _, ok := inHave[l]; !ok {
			fmt.Fprintf(&b, "  - %s\n", l)
		}
	}
	for _, l := range have {
		if _, ok := inWant[l]; !ok {
			fmt.Fprintf(&b, "  + %s\n", l)
		}
	}
	b.WriteString("\nWorkload metric names and label keys are a compatibility surface;\n")
	b.WriteString("see the \"Metrics surface\" section of STABILITY.md. If this change is\n")
	b.WriteString("intended, record it in CHANGELOG.md and regenerate with:\n")
	fmt.Fprintf(&b, "  %s=1 go test ./internal/workloadmetrics/\n", surfaceUpdateEnv)

	t.Error(b.String())
}

func TestDocumentedSurfaceMatchesSnapshot(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "metric-surface.txt"))
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}

	declared := map[string]struct{}{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, _, ok := strings.Cut(line, "{")
		if !ok {
			t.Fatalf("malformed snapshot line %q", line)
		}
		declared[name] = struct{}{}
	}

	docPath := filepath.Join("..", "..", "docs", "continuous-metrics.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}

	documented := map[string]struct{}{}
	for _, m := range regexp.MustCompile("`(podtrace_workload_[a-z0-9_]+|(?:http|rpc|db)_[a-z0-9_]+_seconds)`").FindAllStringSubmatch(string(doc), -1) {
		documented[m[1]] = struct{}{}
	}

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
		t.Errorf("%s is exported but not documented in docs/continuous-metrics.md", name)
	}
	for _, name := range absent {
		t.Errorf("docs/continuous-metrics.md documents %s, which no collector exports", name)
	}
}

func TestLatencyBucketsStayWithinBudgetAssumption(t *testing.T) {
	const maxBuckets = 14
	if len(latencyBuckets) > maxBuckets {
		t.Fatalf("latencyBuckets has %d entries; the per-node series budget in "+
			"internal/config assumes at most %d, and the diagnostic surface's "+
			"20-bucket layout is what this surface exists to avoid",
			len(latencyBuckets), maxBuckets)
	}
	for i := 1; i < len(latencyBuckets); i++ {
		if latencyBuckets[i] <= latencyBuckets[i-1] {
			t.Fatalf("latencyBuckets must be strictly increasing; index %d (%v) <= %d (%v)",
				i, latencyBuckets[i], i-1, latencyBuckets[i-1])
		}
	}
}
