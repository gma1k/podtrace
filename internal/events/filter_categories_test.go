package events

import (
	"reflect"
	"testing"
)

func TestEveryEventTypeHasAFilterCategory(t *testing.T) {
	for et := EventDNS; et <= EventRequestDone; et++ {
		if _, ok := filterCategoryOf[et]; !ok {
			e := &Event{Type: et}
			t.Errorf("%s (type %d) has no filter category, so every --filter and spec.filters drops it", e.TypeString(), et)
		}
	}
}

func TestEveryMappedCategoryIsAKnownFilter(t *testing.T) {
	for et, c := range filterCategoryOf {
		if c != filterCategoryAlways && !IsFilterCategory(c) {
			t.Errorf("type %d maps to unknown category %q", et, c)
		}
	}
}

func TestEveryFilterCategorySelectsAtLeastOneEventType(t *testing.T) {
	for _, c := range FilterCategories() {
		if len(EventTypesInFilterCategory(c)) == 0 {
			t.Errorf("category %q selects no event types", c)
		}
	}
}

func TestOpenAndCloseAreFilesystemEvents(t *testing.T) {
	for _, et := range []EventType{EventOpen, EventClose} {
		if got := FilterCategoryOf(et); got != FilterCategoryFS {
			t.Errorf("FilterCategoryOf(%d) = %q, want fs", et, got)
		}
	}
}

func TestRequestDoneIsDeliveredUnderAnyFilter(t *testing.T) {
	if !DeliveredUnderAnyFilter(EventRequestDone) {
		t.Fatal("RequestDone is not delivered under every filter")
	}
	if got := FilterCategoryOf(EventRequestDone); got != "" {
		t.Fatalf("FilterCategoryOf(RequestDone) = %q, want empty", got)
	}
	if got := EventTypesDeliveredUnderAnyFilter(); !reflect.DeepEqual(got, []EventType{EventRequestDone}) {
		t.Fatalf("EventTypesDeliveredUnderAnyFilter() = %v", got)
	}
	for _, c := range FilterCategories() {
		if !MatchesFilter(EventRequestDone, map[string]bool{c: true}) {
			t.Errorf("RequestDone dropped by filter %q", c)
		}
	}
}

func TestFilterCategoryOfUnknownTypeIsEmpty(t *testing.T) {
	if got := FilterCategoryOf(EventType(9999)); got != "" {
		t.Fatalf("FilterCategoryOf(unknown) = %q", got)
	}
	if DeliveredUnderAnyFilter(EventType(9999)) {
		t.Fatal("unknown type delivered under any filter")
	}
}

func TestEventTypesInFilterCategoryIsSortedAndRejectsUnknown(t *testing.T) {
	got := EventTypesInFilterCategory(FilterCategoryDNS)
	if !reflect.DeepEqual(got, []EventType{EventDNS, EventDNSQuery}) {
		t.Fatalf("dns = %v", got)
	}
	if got := EventTypesInFilterCategory("bogus"); got != nil {
		t.Fatalf("bogus = %v", got)
	}
	if got := EventTypesInFilterCategory(filterCategoryAlways); got != nil {
		t.Fatalf("the always marker is not a category, got %v", got)
	}
}

func TestMatchesFilter(t *testing.T) {
	cases := []struct {
		name       string
		et         EventType
		categories map[string]bool
		want       bool
	}{
		{"empty filter matches everything", EventSchedSwitch, nil, true},
		{"matching category", EventDBQuery, map[string]bool{"net": true}, true},
		{"other category", EventDBQuery, map[string]bool{"fs": true}, false},
		{"unknown type", EventType(9999), map[string]bool{"net": true}, false},
		{"unknown category only", EventDNS, map[string]bool{"bogus": true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchesFilter(tc.et, tc.categories); got != tc.want {
				t.Fatalf("MatchesFilter = %v, want %v", got, tc.want)
			}
		})
	}
}
