package agent

import (
	"reflect"
	"sort"
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/events"
)

func TestTheCRDFilterEnumMatchesTheCanonicalCategories(t *testing.T) {
	fromCRD := append([]string(nil), knownFilterCategories()...)
	want := events.FilterCategories()
	sort.Strings(fromCRD)
	sort.Strings(want)
	if !reflect.DeepEqual(fromCRD, want) {
		t.Fatalf("CRD filters %v, canonical categories %v", fromCRD, want)
	}
}

func TestTheRouterAndTheCLIFilterSelectTheSameEventTypes(t *testing.T) {
	for _, f := range knownFilterCategories() {
		set := filtersToSet([]podtracev1alpha1.EventFilter{podtracev1alpha1.EventFilter(f)})
		for et := events.EventDNS; et <= events.EventRequestDone; et++ {
			_, routed := set[et]
			cli := events.MatchesFilter(et, map[string]bool{f: true})
			if routed != cli {
				e := &events.Event{Type: et}
				t.Errorf("filter %q: %s routed=%v cli=%v", f, e.TypeString(), routed, cli)
			}
		}
	}
}

func TestApplicationEventsReachANetFilteredPodTrace(t *testing.T) {
	set := filtersToSet([]podtracev1alpha1.EventFilter{podtracev1alpha1.FilterNet})
	for _, et := range []events.EventType{
		events.EventDBQuery, events.EventRedisCmd, events.EventMemcachedCmd,
		events.EventKafkaProduce, events.EventKafkaFetch, events.EventPoolAcquire,
		events.EventPoolRelease, events.EventPoolExhausted, events.EventDBAcquire,
		events.EventDBPoolStats, events.EventTLSHandshake, events.EventTLSError,
		events.EventRequestDone,
	} {
		if _, ok := set[et]; !ok {
			e := &events.Event{Type: et}
			t.Errorf("%s dropped by filters: [net]", e.TypeString())
		}
	}
}

func TestUnknownFiltersStillSelectNothing(t *testing.T) {
	if set := filtersToSet([]podtracev1alpha1.EventFilter{"bogus"}); len(set) != 0 {
		t.Fatalf("filtersToSet(bogus) = %v", set)
	}
}
