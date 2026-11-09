package tracker

import (
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestAServiceTargetReportsTheServiceNamespace(t *testing.T) {
	tracker := NewPodCommunicationTracker("client", "shop")
	connect := func(ns string) {
		tracker.ProcessEvent(&events.Event{Type: events.EventConnect, Target: "10.244.1.5:80", Timestamp: uint64(time.Now().UnixNano())},
			map[string]interface{}{
				"target_service":    "web",
				"service_namespace": ns,
				"target_namespace":  "",
			})
	}
	connect("shop")
	connect("payments")

	summaries := tracker.GetSummary()
	if len(summaries) != 2 {
		t.Fatalf("summaries = %+v, want web in shop and web in payments kept apart", summaries)
	}
	seen := map[string]bool{}
	for _, s := range summaries {
		seen[s.Namespace] = true
	}
	if !seen["shop"] || !seen["payments"] {
		t.Fatalf("namespaces = %v, want shop and payments", seen)
	}
}

func TestAPodTargetKeepsItsOwnNamespace(t *testing.T) {
	tracker := NewPodCommunicationTracker("client", "shop")
	tracker.ProcessEvent(&events.Event{Type: events.EventConnect, Target: "10.244.1.6:80", Timestamp: uint64(time.Now().UnixNano())},
		map[string]interface{}{
			"target_pod":        "db-0",
			"target_namespace":  "data",
			"service_namespace": "ignored",
		})
	summaries := tracker.GetSummary()
	if len(summaries) != 1 || summaries[0].Namespace != "data" {
		t.Fatalf("summaries = %+v, want db-0 in data", summaries)
	}
}
