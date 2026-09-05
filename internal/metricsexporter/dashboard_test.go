package metricsexporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const dashboardPath = "dashboard/PodTrace-Dashboard.json"

type dashboardPanel struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	Title   string `json:"title"`
	Targets []struct {
		Expr string `json:"expr"`
	} `json:"targets"`
}

type dashboardFile struct {
	Title  string           `json:"title"`
	Panels []dashboardPanel `json:"panels"`
}

func loadDashboard(t *testing.T) dashboardFile {
	t.Helper()
	raw, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	var d dashboardFile
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("the shipped dashboard is not valid JSON: %v", err)
	}
	return d
}

func TestDashboardPanelIDsAreUnique(t *testing.T) {
	seen := map[int]string{}
	for _, panel := range loadDashboard(t).Panels {
		if previous, clash := seen[panel.ID]; clash {
			t.Errorf("panel id %d is used by both %q and %q; Grafana keys panel state by id "+
				"and a duplicate silently drops one", panel.ID, previous, panel.Title)
		}
		seen[panel.ID] = panel.Title
	}
}

func TestDashboardShipsAServiceMap(t *testing.T) {
	for _, panel := range loadDashboard(t).Panels {
		if panel.Type != "nodeGraph" {
			continue
		}
		if len(panel.Targets) == 0 {
			t.Fatalf("the %q panel has no queries", panel.Title)
		}
		for _, target := range panel.Targets {
			if !strings.Contains(target.Expr, "podtrace_workload_edge_") {
				t.Errorf("the service map queries %q, which is not an edge family. The map is "+
					"a query over metrics that carry both ends of the edge, not a datastore",
					target.Expr)
			}
		}
		return
	}
	t.Error("no nodeGraph panel. The topology is a panel in the shipped dashboard, not a " +
		"separate product surface, so shipping the metrics without it leaves the feature " +
		"invisible to anyone who does not write their own PromQL")
}

func TestEveryDashboardQueryNamesAMetricThatExists(t *testing.T) {
	surface, err := os.ReadFile(filepath.Join("..", "workloadmetrics", "testdata", "metric-surface.txt"))
	if err != nil {
		t.Fatalf("read the workload metric surface: %v", err)
	}
	known := map[string]bool{}
	for _, line := range strings.Split(string(surface), "\n") {
		if name, _, found := strings.Cut(strings.TrimSpace(line), "{"); found {
			known[name] = true
		}
	}
	if len(known) == 0 {
		t.Fatal("parsed no metric names from the surface snapshot; this guard would pass vacuously")
	}

	metricRef := regexp.MustCompile(`podtrace_workload_[a-z0-9_]+`)
	for _, panel := range loadDashboard(t).Panels {
		for _, target := range panel.Targets {
			for _, ref := range metricRef.FindAllString(target.Expr, -1) {
				name := strings.TrimSuffix(strings.TrimSuffix(ref, "_bucket"), "_count")
				name = strings.TrimSuffix(name, "_sum")
				if !known[name] {
					t.Errorf("panel %q queries %q, which the metric surface does not export. "+
						"A renamed metric would otherwise ship as a panel that is silently "+
						"empty forever", panel.Title, name)
				}
			}
		}
	}
}
