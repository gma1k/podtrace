package agent

import (
	"testing"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	"github.com/podtrace/podtrace/internal/events"
)

// TestFiltersToSet_ExpansionsAreStable is a change-detector for the
// filter category → EventType mapping. The agent's per-CR filtering
// depends on this mapping; a silent tweak that (for example) removes
// TCPRecv from the "net" category would quietly stop recording half
// of the network trace.
func TestFiltersToSet_ExpansionsAreStable(t *testing.T) {
	cases := []struct {
		in      []podtracev1alpha1.EventFilter
		wantHas []events.EventType
	}{
		{
			in:      []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterDNS},
			wantHas: []events.EventType{events.EventDNS},
		},
		{
			in: []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterNet},
			wantHas: []events.EventType{
				events.EventConnect, events.EventTCPSend, events.EventTCPRecv,
				events.EventUDPSend, events.EventUDPRecv,
			},
		},
		{
			in: []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterFS},
			wantHas: []events.EventType{
				events.EventOpen, events.EventClose, events.EventRead, events.EventWrite,
			},
		},
		{
			in:      []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterProc},
			wantHas: []events.EventType{events.EventExec, events.EventFork, events.EventOOMKill},
		},
	}
	for _, tc := range cases {
		set := filtersToSet(tc.in)
		for _, want := range tc.wantHas {
			if _, ok := set[want]; !ok {
				t.Errorf("filters=%v: missing expected event type %v", tc.in, want)
			}
		}
	}
}

func TestFiltersToSet_UnionsMultipleCategories(t *testing.T) {
	set := filtersToSet([]podtracev1alpha1.EventFilter{
		podtracev1alpha1.FilterDNS,
		podtracev1alpha1.FilterFS,
	})
	if _, ok := set[events.EventDNS]; !ok {
		t.Error("union missing DNS")
	}
	if _, ok := set[events.EventRead]; !ok {
		t.Error("union missing Read")
	}
}

func TestFiltersToSet_UnknownCategorySkipped(t *testing.T) {
	set := filtersToSet([]podtracev1alpha1.EventFilter{"bogus"})
	if len(set) != 0 {
		t.Errorf("unknown category yielded %d entries, want 0", len(set))
	}
}

func TestLabelsEqual(t *testing.T) {
	cases := []struct {
		name string
		a, b map[string]string
		eq   bool
	}{
		{"both-nil", nil, nil, true},
		{"both-empty", map[string]string{}, map[string]string{}, true},
		{"same", map[string]string{"a": "1"}, map[string]string{"a": "1"}, true},
		{"different-values", map[string]string{"a": "1"}, map[string]string{"a": "2"}, false},
		{"different-keys", map[string]string{"a": "1"}, map[string]string{"b": "1"}, false},
		{"different-lengths", map[string]string{"a": "1"}, map[string]string{"a": "1", "b": "2"}, false},
	}
	for _, tc := range cases {
		if got := labelsEqual(tc.a, tc.b); got != tc.eq {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.eq)
		}
	}
}

func TestCopyMap(t *testing.T) {
	if got := copyMap(nil); got != nil {
		t.Errorf("copyMap(nil)=%v want nil", got)
	}
	src := map[string]string{"a": "1", "b": "2"}
	got := copyMap(src)
	if len(got) != 2 || got["a"] != "1" {
		t.Errorf("copy lost data: %v", got)
	}
	// Mutate the copy, original must be untouched.
	got["a"] = "mutated"
	if src["a"] != "1" {
		t.Error("copyMap did not defensively clone")
	}
}

// TestResolveNodeName verifies the explicit env wins over hostname.
// Hostname fallback is covered in cmd/podtrace/agent_test.go because
// os.Hostname is process-state and mixing with the rest of this file
// would make parallelisation flaky.
func TestResolveNodeName_EnvWins(t *testing.T) {
	t.Setenv("NODE_NAME", "from-env")
	if got := ResolveNodeName(); got != "from-env" {
		t.Errorf("NODE_NAME=%q, want from-env", got)
	}
}
