package formatter

import (
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/analyzer"
)

func TestResolvedAddresses_Empty(t *testing.T) {
	if got := ResolvedAddresses(nil, 5); got != "" {
		t.Errorf("expected empty string for no targets, got %q", got)
	}
}

func TestResolvedAddresses_RendersNamesAndAddrs(t *testing.T) {
	targets := []analyzer.TargetAddrs{
		{Target: "example.com", Addrs: []string{"93.184.216.34", "93.184.216.35"}},
		{Target: "api.internal", Addrs: []string{"10.0.0.1"}},
	}
	result := ResolvedAddresses(targets, 5)
	if !strings.Contains(result, "Resolved addresses:") {
		t.Errorf("missing header, got:\n%s", result)
	}
	if !strings.Contains(result, "example.com -> 93.184.216.34, 93.184.216.35") {
		t.Errorf("multi-address join wrong, got:\n%s", result)
	}
	if !strings.Contains(result, "api.internal -> 10.0.0.1") {
		t.Errorf("single-address render wrong, got:\n%s", result)
	}
}

func TestResolvedAddresses_RespectsLimit(t *testing.T) {
	targets := []analyzer.TargetAddrs{
		{Target: "a.example", Addrs: []string{"1.1.1.1"}},
		{Target: "b.example", Addrs: []string{"2.2.2.2"}},
		{Target: "c.example", Addrs: []string{"3.3.3.3"}},
	}
	result := ResolvedAddresses(targets, 2)
	if strings.Contains(result, "c.example") {
		t.Errorf("limit not enforced; c.example should be dropped:\n%s", result)
	}
	if !strings.Contains(result, "a.example") || !strings.Contains(result, "b.example") {
		t.Errorf("first two entries must be present:\n%s", result)
	}
}

func TestTopItemsWithRate_Empty(t *testing.T) {
	if got := TopItemsWithRate(map[string]int{}, 5, "urls", "requests", time.Second); got != "" {
		t.Errorf("expected empty string for no items, got %q", got)
	}
}

func TestTopItemsWithRate_RespectsLimit(t *testing.T) {
	items := map[string]int{"GET /a": 50, "GET /b": 40, "GET /c": 30}
	result := TopItemsWithRate(items, 1, "requested URLs", "requests", 10*time.Second)
	if strings.Count(result, "    - ") != 1 {
		t.Errorf("expected exactly one item at limit 1, got:\n%s", result)
	}
	if !strings.Contains(result, "GET /a") {
		t.Errorf("highest-count item must be kept, got:\n%s", result)
	}
}
