package detector

import (
	"fmt"
	"reflect"
	"testing"
)

func ref(id ID, workload string) IssueRef {
	return IssueRef{ID: id, Namespace: "shop", Workload: workload}
}

func calls(graph map[string][]string) func(string, string) []IssueRef {
	return func(namespace, workload string) []IssueRef {
		var out []IssueRef
		for _, w := range graph[workload] {
			out = append(out, IssueRef{Namespace: namespace, Workload: w})
		}
		return out
	}
}

func TestASaturatedPoolExplainsSlowRequestsOnItsWorkload(t *testing.T) {
	latency, pool := ref(IDL7LatencyDegraded, "api"), ref(IDDBPoolSaturated, "api")
	got := RootCauses([]IssueRef{latency, pool}, nil)
	want := map[IssueRef][]Cause{latency: {{IssueRef: pool}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestEveryLocalLinkInTheTableIsFollowed(t *testing.T) {
	for symptom, causes := range LocalCauses {
		for _, cause := range causes {
			s, c := ref(symptom, "api"), ref(cause, "api")
			got := RootCauses([]IssueRef{s, c}, nil)[s]
			if len(got) != 1 || got[0].IssueRef != c || len(got[0].Via) != 0 {
				t.Errorf("%s with %s: causes %v", symptom, cause, got)
			}
		}
	}
}

func TestAPairTheTableDoesNotListIsNotLinked(t *testing.T) {
	got := RootCauses([]IssueRef{ref(IDL7LatencyDegraded, "api"), ref(IDDNSFailureRate, "api")}, nil)
	if len(got) != 0 {
		t.Errorf("got %v, want no links", got)
	}
}

func TestIssuesOnUnrelatedWorkloadsAreNotLinked(t *testing.T) {
	got := RootCauses([]IssueRef{ref(IDL7LatencyDegraded, "api"), ref(IDDBPoolSaturated, "billing")}, calls(nil))
	if len(got) != 0 {
		t.Errorf("got %v, want no links", got)
	}
}

func TestTheRootIsReportedNotTheIssueInBetween(t *testing.T) {
	latency, acquire, pool := ref(IDL7LatencyDegraded, "api"), ref(IDDBAcquireSlow, "api"), ref(IDDBPoolSaturated, "api")
	got := RootCauses([]IssueRef{latency, acquire, pool}, nil)
	if want := []Cause{{IssueRef: pool}}; !reflect.DeepEqual(got[latency], want) {
		t.Errorf("latency causes %v, want %v", got[latency], want)
	}
	if want := []Cause{{IssueRef: pool}}; !reflect.DeepEqual(got[acquire], want) {
		t.Errorf("acquire causes %v, want %v", got[acquire], want)
	}
	if _, ok := got[pool]; ok {
		t.Errorf("the pool, which nothing explains, was given causes %v", got[pool])
	}
}

func TestACallerIsSlowBecauseTheDependencyItCallsIsSlow(t *testing.T) {
	front, backend, pool := ref(IDL7LatencyDegraded, "front"), ref(IDL7LatencyDegraded, "backend"), ref(IDDBPoolSaturated, "backend")
	got := RootCauses([]IssueRef{front, backend, pool}, calls(map[string][]string{"front": {"backend"}}))
	if want := []Cause{{IssueRef: pool, Via: []IssueRef{backend}}}; !reflect.DeepEqual(got[front], want) {
		t.Errorf("front causes %v, want %v", got[front], want)
	}
	if want := []Cause{{IssueRef: pool}}; !reflect.DeepEqual(got[backend], want) {
		t.Errorf("backend causes %v, want %v", got[backend], want)
	}
}

func TestADependencyIsBlamedOnlyThroughItsMatchingIssue(t *testing.T) {
	front, backendErrors := ref(IDL7LatencyDegraded, "front"), ref(IDL7ErrorRate, "backend")
	got := RootCauses([]IssueRef{front, backendErrors}, calls(map[string][]string{"front": {"backend"}}))
	if len(got) != 0 {
		t.Errorf("got %v: a dependency's errors do not explain a caller's latency", got)
	}
	frontErrors := ref(IDL7ErrorRate, "front")
	got = RootCauses([]IssueRef{frontErrors, backendErrors}, calls(map[string][]string{"front": {"backend"}}))
	if want := []Cause{{IssueRef: backendErrors}}; !reflect.DeepEqual(got[frontErrors], want) {
		t.Errorf("front error causes %v, want %v", got[frontErrors], want)
	}
}

func TestADependencyThatIsNotCalledIsNotBlamed(t *testing.T) {
	front, backend := ref(IDL7LatencyDegraded, "front"), ref(IDL7LatencyDegraded, "backend")
	got := RootCauses([]IssueRef{front, backend}, calls(map[string][]string{"backend": {"front"}}))
	if _, ok := got[front]; ok {
		t.Errorf("front was blamed on a workload it does not call: %v", got[front])
	}
}

func TestTwoWorkloadsCallingEachOtherStopAtTheCycle(t *testing.T) {
	a, b := ref(IDL7LatencyDegraded, "a"), ref(IDL7LatencyDegraded, "b")
	got := RootCauses([]IssueRef{a, b}, calls(map[string][]string{"a": {"b"}, "b": {"a"}}))
	want := map[IssueRef][]Cause{a: {{IssueRef: b}}, b: {{IssueRef: a}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAWorkloadCallingItselfIsNotItsOwnCause(t *testing.T) {
	a := ref(IDL7LatencyDegraded, "a")
	got := RootCauses([]IssueRef{a}, calls(map[string][]string{"a": {"a"}}))
	if len(got) != 0 {
		t.Errorf("got %v, want no links", got)
	}
}

func TestTheSameIssueOnSeveralPodsIsOneIssue(t *testing.T) {
	latency, pool := ref(IDL7LatencyDegraded, "api"), ref(IDDBPoolSaturated, "api")
	got := RootCauses([]IssueRef{latency, pool, latency, pool}, nil)
	if want := []Cause{{IssueRef: pool}}; !reflect.DeepEqual(got[latency], want) {
		t.Errorf("got %v, want %v", got[latency], want)
	}
}

func TestSeveralRootsAreAllReportedNearestFirst(t *testing.T) {
	front := ref(IDL7LatencyDegraded, "front")
	cpu := ref(IDCPUContention, "front")
	backend, pool := ref(IDL7LatencyDegraded, "backend"), ref(IDDBPoolSaturated, "backend")
	got := RootCauses([]IssueRef{front, cpu, backend, pool}, calls(map[string][]string{"front": {"backend"}}))
	want := []Cause{{IssueRef: cpu}, {IssueRef: pool, Via: []IssueRef{backend}}}
	if !reflect.DeepEqual(got[front], want) {
		t.Errorf("got %v, want %v", got[front], want)
	}
}

func TestTheShortestChainToARootIsKept(t *testing.T) {
	front := ref(IDL7LatencyDegraded, "front")
	mid, back := ref(IDL7LatencyDegraded, "mid"), ref(IDL7LatencyDegraded, "back")
	graph := calls(map[string][]string{"front": {"mid", "back"}, "mid": {"back"}})
	got := RootCauses([]IssueRef{front, mid, back}, graph)
	if want := []Cause{{IssueRef: back}}; !reflect.DeepEqual(got[front], want) {
		t.Errorf("got %v, want %v", got[front], want)
	}
}

func TestALongChainIsCutAtTheDepthBound(t *testing.T) {
	var active []IssueRef
	graph := map[string][]string{}
	for i := 0; i < 12; i++ {
		active = append(active, ref(IDL7LatencyDegraded, fmt.Sprint("w", i)))
		graph[fmt.Sprint("w", i)] = []string{fmt.Sprint("w", i+1)}
	}
	got := RootCauses(active, calls(graph))[active[0]]
	if len(got) != 1 || got[0].IssueRef != active[maxCauseDepth] || len(got[0].Via) != maxCauseDepth-1 {
		t.Errorf("got %v, want the chain cut at %s", got, active[maxCauseDepth])
	}
}

func TestADenseCallGraphStaysCheap(t *testing.T) {
	var active []IssueRef
	graph := map[string][]string{}
	for i := 0; i < 60; i++ {
		w := fmt.Sprint("w", i)
		active = append(active, ref(IDL7LatencyDegraded, w))
		for j := 0; j < 60; j++ {
			if j != i {
				graph[w] = append(graph[w], fmt.Sprint("w", j))
			}
		}
	}
	got := RootCauses(active, calls(graph))
	if len(got) != len(active) {
		t.Errorf("%d issues have causes, want all %d", len(got), len(active))
	}
}

func TestACauseReadsFromTheRootThroughTheChain(t *testing.T) {
	c := Cause{IssueRef: ref(IDDBPoolSaturated, "backend"), Via: []IssueRef{ref(IDL7LatencyDegraded, "mid"), ref(IDL7LatencyDegraded, "backend")}}
	want := "db.pool_saturated on shop/backend, through l7.latency_degraded on shop/backend, through l7.latency_degraded on shop/mid"
	if got := c.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestAnIssueRefersToItsWorkload(t *testing.T) {
	is := Issue{ID: IDCPUContention, Subject: Subject{Namespace: "shop", Workload: "api", Pod: "api-1", Container: "c", Resource: "cpu"}}
	if got := is.Ref(); got != ref(IDCPUContention, "api") {
		t.Errorf("got %v", got)
	}
}

func TestEveryIssueInTheCauseTablesIsRegistered(t *testing.T) {
	registered := map[ID]bool{}
	for _, id := range Registry {
		registered[id] = true
	}
	for _, table := range []map[ID][]ID{LocalCauses, DependencyCauses} {
		for symptom, causes := range table {
			for _, id := range append([]ID{symptom}, causes...) {
				if !registered[id] {
					t.Errorf("%s is in a cause table but not in the Registry", id)
				}
			}
		}
	}
}
