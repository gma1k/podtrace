package status

import (
	"context"
	"testing"
)

func TestLiveIssuesAreReadThroughThePodProxy(t *testing.T) {
	s := &apiServer{t: t, issues: []byte(`{"issues":[{"id":"dns.failure_rate","severity":"warning","namespace":"shop","workload":"resolver","pod":"resolver-0","since":"2026-10-07T09:00:00Z","message":"mostly SERVFAIL"}]}`)}
	k := &KubeCluster{Client: s.start(), SystemNamespace: "podtrace-system"}
	live, err := k.ActiveIssues(context.Background(), Agent{Name: "a", Port: 9090})
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 || live[0].Message != "mostly SERVFAIL" || live[0].Since.IsZero() {
		t.Errorf("live = %+v", live)
	}
	if want := "/api/v1/namespaces/podtrace-system/pods/a:9090/proxy/issues"; s.paths[0] != want {
		t.Errorf("path = %q, want %q", s.paths[0], want)
	}
}

func TestAnAgentWithoutTheEndpointIsAnErrorTheCallerFallsBackOn(t *testing.T) {
	older := &apiServer{t: t}
	if _, err := (&KubeCluster{Client: older.start(), SystemNamespace: "podtrace-system"}).ActiveIssues(context.Background(), Agent{Name: "a", Port: 9090}); err == nil {
		t.Error("an agent that answered 404 was read as having no issues")
	}
	bad := &apiServer{t: t, issues: []byte("<html>")}
	if _, err := (&KubeCluster{Client: bad.start(), SystemNamespace: "podtrace-system"}).ActiveIssues(context.Background(), Agent{Name: "a", Port: 9090}); err == nil {
		t.Error("an unreadable body was accepted")
	}
}
