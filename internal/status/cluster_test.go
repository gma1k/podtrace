package status

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/inspect"
	"github.com/gma1k/podtrace/internal/profiling"
)

func agentPod(name, node string, ready bool, restarts int32, port int32) *corev1.Pod {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "podtrace-system", Labels: map[string]string{
			"podtrace.io/component": "agent", tracerConfigLabel: "default",
		}},
		Spec: corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "agent", Ports: []corev1.ContainerPort{
			{Name: "health", ContainerPort: 9091}, {Name: metricsPortName, ContainerPort: port},
		}}}},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			Conditions:        []corev1.PodCondition{{Type: corev1.PodReady, Status: status}},
			ContainerStatuses: []corev1.ContainerStatus{{RestartCount: restarts}},
		},
	}
}

func TestAgentsAreReadFromTheirPods(t *testing.T) {
	other := agentPod("not-an-agent", "n9", true, 0, 9090)
	other.Labels = map[string]string{}
	cs := fake.NewClientset(agentPod("a", "n1", true, 2, 9095), agentPod("b", "n2", false, 0, 9090), other)
	k := &KubeCluster{Client: cs, SystemNamespace: "podtrace-system"}

	agents, err := k.Agents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 2 {
		t.Fatalf("agents = %+v, want the two labelled agent pods", agents)
	}
	byName := map[string]Agent{}
	for _, a := range agents {
		byName[a.Name] = a
	}
	if a := byName["a"]; !a.Ready || a.Restarts != 2 || a.Port != 9095 || a.Node != "n1" || a.Fleet != "default" {
		t.Errorf("a = %+v; the metrics port must come from the pod, not be assumed", a)
	}
	if byName["b"].Ready {
		t.Error("an unready pod was reported ready")
	}
}

func TestAPodWithoutANamedMetricsPortUsesTheDefault(t *testing.T) {
	p := agentPod("a", "n1", true, 0, 9090)
	p.Spec.Containers[0].Ports = nil
	if got := agentOf(p).Port; got != defaultMetricsPort {
		t.Errorf("port = %d", got)
	}
}

func TestListFailuresAreReturned(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unavailable")
	})
	k := &KubeCluster{Client: cs, SystemNamespace: "podtrace-system"}
	if _, err := k.Agents(context.Background()); err == nil {
		t.Error("a failed pod list was reported as no agents")
	}
	if _, err := k.IssueEvents(context.Background(), "shop"); err == nil {
		t.Error("a failed event list was reported as no events")
	}
}

func TestOnlyIssueEventsAreReturned(t *testing.T) {
	issue := corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Name: "e1", Namespace: "shop", Annotations: map[string]string{alerting.AnnotationAlertSource: alerting.AlertSourceIssue}},
		Reason:     alerting.EventReasonAlert,
	}
	resource := issue
	resource.Name = "e2"
	resource.Annotations = map[string]string{alerting.AnnotationAlertSource: alerting.AlertSourceResourceMonitor}
	unrelated := issue
	unrelated.Name = "e3"
	unrelated.Reason = "Pulled"
	k := &KubeCluster{Client: fake.NewClientset(&issue, &resource, &unrelated), SystemNamespace: "podtrace-system"}

	got, err := k.IssueEvents(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "e1" {
		t.Errorf("events = %+v, want only the issue Event", got)
	}
}

type apiServer struct {
	t       *testing.T
	metrics []byte
	mtype   string
	profile []byte
	issues  []byte
	status  int
	accept  string
	paths   []string
	queries []string
}

func (s *apiServer) start() kubernetes.Interface {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.paths = append(s.paths, r.URL.Path)
		s.queries = append(s.queries, r.URL.RawQuery)
		if s.status != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(s.status)
			_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`))
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/proxy/metrics"):
			s.accept = r.Header.Get("Accept")
			w.Header().Set("Content-Type", s.mtype)
			_, _ = w.Write(s.metrics)
		case strings.HasSuffix(r.URL.Path, "/proxy/profile"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(s.profile)
		case strings.HasSuffix(r.URL.Path, "/proxy/issues") && s.issues != nil:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(s.issues)
		default:
			http.NotFound(w, r)
		}
	}))
	s.t.Cleanup(srv.Close)
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		s.t.Fatal(err)
	}
	return cs
}

func encode(t *testing.T, families []*dto.MetricFamily, format expfmt.Format) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, format)
	for _, f := range families {
		if err := enc.Encode(f); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestAScrapeGoesThroughThePodProxyAndKeepsNativeHistograms(t *testing.T) {
	m := newAgentMetrics(true)
	m.serve("shop", "checkout", 100, 0, 200*time.Millisecond)
	format := expfmt.NewFormat(expfmt.TypeProtoDelim)
	s := &apiServer{t: t, metrics: encode(t, m.families(t), format), mtype: string(format)}
	k := &KubeCluster{Client: s.start(), SystemNamespace: "podtrace-system"}

	families, err := k.Scrape(context.Background(), Agent{Name: "podtrace-agent-x", Port: 9090})
	if err != nil {
		t.Fatal(err)
	}
	if want := "/api/v1/namespaces/podtrace-system/pods/podtrace-agent-x:9090/proxy/metrics"; len(s.paths) != 1 || s.paths[0] != want {
		t.Errorf("paths = %v, want %s", s.paths, want)
	}
	if !strings.HasPrefix(s.accept, "application/vnd.google.protobuf") {
		t.Errorf("Accept = %q; the text format drops native histograms", s.accept)
	}
	snap := inspect.TakeFamilies(families, time.Now())
	samples := snap.Family(familyL7Duration)
	if len(samples) != 1 || !samples[0].NativeBuckets || samples[0].Count != 100 {
		t.Errorf("duration samples = %+v; the native histogram did not survive the proxy", samples)
	}
}

func TestATextScrapeIsStillRead(t *testing.T) {
	m := newAgentMetrics(false)
	m.serve("shop", "checkout", 5, 0, time.Millisecond)
	format := expfmt.NewFormat(expfmt.TypeTextPlain)
	s := &apiServer{t: t, metrics: encode(t, m.families(t), format), mtype: string(format)}
	families, err := (&KubeCluster{Client: s.start(), SystemNamespace: "podtrace-system"}).Scrape(context.Background(), Agent{Name: "a", Port: 9090})
	if err != nil {
		t.Fatal(err)
	}
	if snap := inspect.TakeFamilies(families, time.Now()); len(snap.Family(familyL7Requests)) != 1 {
		t.Errorf("requests family missing from a text scrape")
	}
}

func TestAnUnreadableScrapeIsAnError(t *testing.T) {
	for name, s := range map[string]*apiServer{
		"bad text":     {metrics: []byte("this is { not metrics"), mtype: "text/plain; version=0.0.4"},
		"bad protobuf": {metrics: []byte{0x05, 0x01, 0x02}, mtype: string(expfmt.NewFormat(expfmt.TypeProtoDelim))},
		"forbidden":    {status: http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			s.t = t
			if _, err := (&KubeCluster{Client: s.start(), SystemNamespace: "podtrace-system"}).Scrape(context.Background(), Agent{Name: "a", Port: 9090}); err == nil {
				t.Error("no error")
			}
		})
	}
}

func TestAProfileGoesThroughThePodProxy(t *testing.T) {
	body, _ := json.Marshal(Profile{Profiles: []profiling.WorkloadProfile{{Namespace: "shop", Workload: "checkout", Samples: 7}}, Dropped: 1})
	s := &apiServer{t: t, profile: body}
	k := &KubeCluster{Client: s.start(), SystemNamespace: "podtrace-system"}

	p, err := k.Profile(context.Background(), Agent{Name: "a", Port: 9090})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Profiles) != 1 || p.Profiles[0].Samples != 7 || p.Dropped != 1 {
		t.Errorf("profile = %+v", p)
	}

	bad := &apiServer{t: t, profile: []byte("<html>")}
	if _, err := (&KubeCluster{Client: bad.start(), SystemNamespace: "podtrace-system"}).Profile(context.Background(), Agent{Name: "a", Port: 9090}); err == nil {
		t.Error("an unreadable profile was accepted")
	}
	denied := &apiServer{t: t, status: http.StatusForbidden}
	if _, err := (&KubeCluster{Client: denied.start(), SystemNamespace: "podtrace-system"}).Profile(context.Background(), Agent{Name: "a", Port: 9090}); err == nil {
		t.Error("a forbidden profile read was accepted")
	}
}
