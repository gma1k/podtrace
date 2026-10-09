package status

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

var (
	poolOnBackend    = detector.IssueRef{ID: detector.IDDBPoolSaturated, Namespace: "shop", Workload: "backend"}
	latencyOnBackend = detector.IssueRef{ID: detector.IDL7LatencyDegraded, Namespace: "shop", Workload: "backend"}
	cpuOnFront       = detector.IssueRef{ID: detector.IDCPUContention, Namespace: "shop", Workload: "front"}
)

func frontIsSlow(t *testing.T, causes []detector.Cause) AgentScrape {
	m := newAgentMetrics(false)
	m.raise("l7.latency_degraded", "shop", "front", "", "warning")
	return AgentScrape{
		Agent: agent("a", "n1"), Window: window(t, m, func() {}), LiveRead: true,
		Live: []LiveIssue{{ID: "l7.latency_degraded", Severity: "warning", Namespace: "shop", Workload: "front",
			Pod: "front-0", Since: t0, Message: "slow", Causes: causes}},
	}
}

func TestAnIssueCarriesTheCausesItsAgentFound(t *testing.T) {
	r := Build([]AgentScrape{frontIsSlow(t, []detector.Cause{{IssueRef: cpuOnFront}})}, nil, Options{}, t0)
	if want := []detector.Cause{{IssueRef: cpuOnFront}}; !reflect.DeepEqual(r.Issues[0].Causes, want) {
		t.Errorf("causes %v, want %v", r.Issues[0].Causes, want)
	}
}

func TestTheOperatorsClusterWideCausesReplaceTheAgents(t *testing.T) {
	r := Build([]AgentScrape{frontIsSlow(t, []detector.Cause{{IssueRef: cpuOnFront}})}, nil, Options{}, t0)
	operator := []detector.Cause{{IssueRef: cpuOnFront}, {IssueRef: poolOnBackend, Via: []detector.IssueRef{latencyOnBackend}}}
	r.AttachCauses(Correlation{Issues: []CorrelatedIssue{
		{IssueRef: detector.IssueRef{ID: detector.IDL7LatencyDegraded, Namespace: "shop", Workload: "front"}, Causes: operator},
	}})
	if !reflect.DeepEqual(r.Issues[0].Causes, operator) {
		t.Errorf("causes %v, want the operator's %v", r.Issues[0].Causes, operator)
	}
}

func TestAnIssueTheOperatorHasNotSeenKeepsItsAgentsCauses(t *testing.T) {
	r := Build([]AgentScrape{frontIsSlow(t, []detector.Cause{{IssueRef: cpuOnFront}})}, nil, Options{}, t0)
	r.AttachCauses(Correlation{Issues: []CorrelatedIssue{{IssueRef: poolOnBackend}}})
	if want := []detector.Cause{{IssueRef: cpuOnFront}}; !reflect.DeepEqual(r.Issues[0].Causes, want) {
		t.Errorf("causes %v, want the agent's %v", r.Issues[0].Causes, want)
	}
}

func collectWith(t *testing.T, raised bool, correlation *Correlation) Report {
	t.Helper()
	m := newAgentMetrics(false)
	if raised {
		m.raise("l7.latency_degraded", "shop", "front", "front-0", "warning")
	}
	fc := &fakeCluster{
		agents:      []Agent{agent("a", "n1")},
		scrape:      func(Agent, int) ([]*dto.MetricFamily, error) { return m.families(t), nil },
		correlation: correlation,
	}
	c := &Collector{Cluster: fc, Sleep: func(context.Context, time.Duration) error { return nil }, Now: func() time.Time { return t0 }}
	r, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTheCollectorAttachesTheOperatorsCauses(t *testing.T) {
	cause := []detector.Cause{{IssueRef: poolOnBackend, Via: []detector.IssueRef{latencyOnBackend}}}
	r := collectWith(t, true, &Correlation{Issues: []CorrelatedIssue{
		{IssueRef: detector.IssueRef{ID: detector.IDL7LatencyDegraded, Namespace: "shop", Workload: "front"}, Causes: cause},
	}})
	if len(r.Issues) != 1 || !reflect.DeepEqual(r.Issues[0].Causes, cause) {
		t.Errorf("issues %+v", r.Issues)
	}
	for _, w := range r.Warnings {
		if strings.Contains(w, "correlation") {
			t.Errorf("warned %q though the correlation was read", w)
		}
	}
}

func TestAnUnreadableCorrelationIsAWarningOnlyWhenThereAreIssues(t *testing.T) {
	warned := func(r Report) bool {
		for _, w := range r.Warnings {
			if strings.Contains(w, "operator's issue correlation") {
				return true
			}
		}
		return false
	}
	if r := collectWith(t, true, nil); !warned(r) {
		t.Errorf("warnings %v, want the missing correlation said", r.Warnings)
	}
	if r := collectWith(t, false, nil); warned(r) {
		t.Errorf("warnings %v: nothing to explain, so nothing is missing", r.Warnings)
	}
}

func TestTheLikelyCausesAreListedOncePerWorkloadIssue(t *testing.T) {
	cause := detector.Cause{IssueRef: poolOnBackend, Via: []detector.IssueRef{latencyOnBackend}}
	r := Report{GeneratedAt: t0, Issues: []Issue{
		{ID: "l7.latency_degraded", Severity: "warning", Namespace: "shop", Workload: "front", Pod: "front-0", Causes: []detector.Cause{cause}},
		{ID: "l7.latency_degraded", Severity: "warning", Namespace: "shop", Workload: "front", Pod: "front-1", Causes: []detector.Cause{cause}},
	}}
	var b strings.Builder
	if err := RenderText(&b, r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "LIKELY CAUSES") {
		t.Fatalf("no likely causes section:\n%s", out)
	}
	if n := strings.Count(out, "db.pool_saturated on shop/backend, through l7.latency_degraded on shop/backend"); n != 1 {
		t.Errorf("the cause appears %d times, want once:\n%s", n, out)
	}
}

func TestNoLikelyCausesSectionWithoutCauses(t *testing.T) {
	r := Report{GeneratedAt: t0, Issues: []Issue{{ID: "l7.latency_degraded", Severity: "warning", Namespace: "shop", Workload: "front"}}}
	var b strings.Builder
	if err := RenderText(&b, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "LIKELY CAUSES") {
		t.Errorf("a likely causes section with nothing in it:\n%s", b.String())
	}
}

type operatorAPI struct {
	pods     []corev1.Pod
	bodies   map[string]string
	paths    []string
	listFail bool
}

func (o *operatorAPI) start(t *testing.T) kubernetes.Interface {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.paths = append(o.paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/namespaces/podtrace-system/pods" {
			if o.listFail {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`))
				return
			}
			_ = json.NewEncoder(w).Encode(corev1.PodList{Items: o.pods})
			return
		}
		for name, body := range o.bodies {
			if strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/podtrace-system/pods/"+name+":") && strings.HasSuffix(r.URL.Path, "/proxy/correlations") {
				_, _ = w.Write([]byte(body))
				return
			}
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","code":503}`))
	}))
	t.Cleanup(srv.Close)
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func operatorPod(name string, phase corev1.PodPhase, port int32) corev1.Pod {
	p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "podtrace-system"}, Status: corev1.PodStatus{Phase: phase}}
	if port != 0 {
		p.Spec.Containers = []corev1.Container{{Ports: []corev1.ContainerPort{{Name: "metrics", ContainerPort: port}}}}
	}
	return p
}

func TestTheCorrelationIsReadFromTheOperatorThatHasOne(t *testing.T) {
	api := &operatorAPI{
		pods: []corev1.Pod{
			operatorPod("standby", corev1.PodRunning, 8080),
			operatorPod("starting", corev1.PodPending, 8080),
			operatorPod("leader", corev1.PodRunning, 0),
		},
		bodies: map[string]string{"leader": `{"agentsRead":3,"issues":[{"id":"db.pool_saturated","namespace":"shop","workload":"backend"}]}`},
	}
	k := &KubeCluster{Client: api.start(t), SystemNamespace: "podtrace-system"}
	c, err := k.Correlations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.AgentsRead != 3 || len(c.Issues) != 1 || c.Issues[0].IssueRef != poolOnBackend {
		t.Errorf("correlation %+v", c)
	}
	for _, p := range api.paths {
		if strings.Contains(p, "starting") {
			t.Errorf("a pod that is not running was read: %s", p)
		}
	}
	want := "/api/v1/namespaces/podtrace-system/pods/leader:8080/proxy/correlations"
	if api.paths[len(api.paths)-1] != want {
		t.Errorf("last read %s, want %s", api.paths[len(api.paths)-1], want)
	}
}

func TestNoOperatorWithACorrelationIsAnError(t *testing.T) {
	none := &operatorAPI{}
	if _, err := (&KubeCluster{Client: none.start(t), SystemNamespace: "podtrace-system"}).Correlations(context.Background()); err == nil {
		t.Error("no operator pod, and no error")
	}
	garbled := &operatorAPI{pods: []corev1.Pod{operatorPod("op", corev1.PodRunning, 8080)}, bodies: map[string]string{"op": "<html>"}}
	if _, err := (&KubeCluster{Client: garbled.start(t), SystemNamespace: "podtrace-system"}).Correlations(context.Background()); err == nil {
		t.Error("an unreadable correlation was accepted")
	}
	forbidden := &operatorAPI{listFail: true}
	if _, err := (&KubeCluster{Client: forbidden.start(t), SystemNamespace: "podtrace-system"}).Correlations(context.Background()); err == nil {
		t.Error("a forbidden pod list was read as no correlation")
	}
	standby := &operatorAPI{pods: []corev1.Pod{operatorPod("op", corev1.PodRunning, 8080)}}
	if _, err := (&KubeCluster{Client: standby.start(t), SystemNamespace: "podtrace-system"}).Correlations(context.Background()); err == nil {
		t.Error("a replica without a correlation was accepted")
	}
}
