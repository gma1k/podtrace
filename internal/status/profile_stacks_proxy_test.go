package status

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/gma1k/podtrace/internal/profiling"
)

func TestStacksAreReadThroughThePodProxyWithTheSelection(t *testing.T) {
	s := &apiServer{t: t, profile: []byte("shop/checkout;f 1\n")}
	k := &KubeCluster{Client: s.start(), SystemNamespace: "podtrace-system"}

	raw, err := k.ProfileStacks(context.Background(), Agent{Name: "a", Port: 9090}, StackFormatFolded,
		profiling.StackSelection{Namespace: "shop", Workload: "checkout", SlowRequests: true})
	if err != nil || string(raw) != "shop/checkout;f 1\n" {
		t.Fatalf("ProfileStacks = %q, %v", raw, err)
	}
	q, _ := url.ParseQuery(s.queries[0])
	if s.paths[0] != "/api/v1/namespaces/podtrace-system/pods/a:9090/proxy/profile" ||
		q.Get("format") != "folded" || q.Get("namespace") != "shop" || q.Get("workload") != "checkout" || q.Get("requests") != "slow" {
		t.Errorf("path %s, query %s", s.paths[0], s.queries[0])
	}

	all := &apiServer{t: t, profile: []byte{}}
	_, _ = (&KubeCluster{Client: all.start(), SystemNamespace: "podtrace-system"}).ProfileStacks(context.Background(),
		Agent{Name: "a", Port: 9090}, StackFormatPprof, profiling.StackSelection{})
	if q, _ := url.ParseQuery(all.queries[0]); q.Has("requests") || q.Get("format") != "pprof" {
		t.Errorf("query %s; all requests is the default and needs no parameter", all.queries[0])
	}

	denied := &apiServer{t: t, status: http.StatusForbidden}
	if _, err := (&KubeCluster{Client: denied.start(), SystemNamespace: "podtrace-system"}).ProfileStacks(context.Background(),
		Agent{Name: "a", Port: 9090}, StackFormatFolded, profiling.StackSelection{}); err == nil {
		t.Error("a forbidden read was accepted")
	}
}
