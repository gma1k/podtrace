package status

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func healthyComponents() []Component {
	return []Component{
		{Kind: KindFleet, Name: "podtrace-agent", Fleet: "default", Desired: 3, Ready: 3, Updated: 3},
		{Kind: KindOperator, Name: "podtrace-operator", Desired: 1, Ready: 1, Updated: 1},
	}
}

func okReport(t *testing.T) Report {
	t.Helper()
	return Build([]AgentScrape{{Agent: agent("a", "n1"), Window: window(t, newAgentMetrics(false), func() {})}}, nil, Options{}, t0)
}

func TestAHealthyInstallIsHealthy(t *testing.T) {
	r := okReport(t)
	r.Assess(healthyComponents(), nil)
	if !r.Healthy || len(r.Problems) != 0 {
		t.Fatalf("healthy=%v problems=%v", r.Healthy, r.Problems)
	}
	if len(r.Components) != 2 || r.Components[0].Kind != KindOperator || r.Components[1].State != StateOK {
		t.Errorf("components = %+v, want the operator first and every component ok", r.Components)
	}
}

func TestEachUnhealthyComponentIsAProblem(t *testing.T) {
	for name, tt := range map[string]struct {
		components []Component
		want       string
	}{
		"no operator":             {[]Component{{Kind: KindFleet, Name: "f", Desired: 1, Ready: 1, Updated: 1}}, "no podtrace operator found"},
		"operator scaled to zero": {[]Component{{Kind: KindOperator, Name: "op", Desired: 0}}, "operator op is scaled to zero"},
		"operator unavailable":    {[]Component{{Kind: KindOperator, Name: "op", Desired: 1, Ready: 0, Updated: 1}}, "operator op: 0 of 1 ready"},
		"fleet rolling out": {append([]Component{{Kind: KindOperator, Name: "op", Desired: 1, Ready: 1, Updated: 1}},
			Component{Kind: KindFleet, Name: "podtrace-agent", Desired: 3, Ready: 3, Updated: 1}), "fleet podtrace-agent: 3 of 3 ready, 1 updated"},
	} {
		t.Run(name, func(t *testing.T) {
			r := okReport(t)
			r.Assess(tt.components, nil)
			if r.Healthy || !strings.Contains(strings.Join(r.Problems, " "), tt.want) {
				t.Errorf("healthy=%v problems=%v, want one saying %q", r.Healthy, r.Problems, tt.want)
			}
		})
	}
}

func TestAFleetWithNoNodesIsAWarningNotAProblem(t *testing.T) {
	r := okReport(t)
	r.Assess(append(healthyComponents(), Component{Kind: KindFleet, Name: "podtrace-agent-gpu", Desired: 0}), nil)
	if !r.Healthy {
		t.Errorf("problems = %v; a node pool scaled to zero is not podtrace being broken", r.Problems)
	}
	if !strings.Contains(strings.Join(r.Warnings, " "), "podtrace-agent-gpu schedules no agents") {
		t.Errorf("warnings = %v", r.Warnings)
	}
}

func TestComponentsThatCannotBeListedAreAWarning(t *testing.T) {
	r := okReport(t)
	r.Assess(nil, errors.New("deployments.apps is forbidden"))
	if !r.Healthy {
		t.Errorf("problems = %v; not being allowed to check the operator is not the operator being down", r.Problems)
	}
	if !strings.Contains(strings.Join(r.Warnings, " "), "only the agents were") {
		t.Errorf("warnings = %v", r.Warnings)
	}
}

func TestEveryAgentThatIsNotOkIsAProblem(t *testing.T) {
	notReady := agent("b", "n2")
	notReady.Ready = false
	r := Build([]AgentScrape{
		{Agent: agent("a", "n1"), Err: errors.New("dial tcp: connection refused")},
		{Agent: notReady, Window: window(t, newAgentMetrics(false), func() {})},
	}, nil, Options{}, t0)
	r.Assess(healthyComponents(), nil)
	got := strings.Join(r.Problems, " | ")
	if r.Healthy || !strings.Contains(got, "agent on n1 is unreachable: dial tcp") || !strings.Contains(got, "agent on n2 is not ready") {
		t.Errorf("problems = %v", r.Problems)
	}
	none := Build(nil, nil, Options{}, t0)
	none.Assess(healthyComponents(), nil)
	if none.Healthy {
		t.Error("an install with no agents at all was healthy")
	}
}

func TestAssessingTwiceDoesNotStackProblems(t *testing.T) {
	r := okReport(t)
	r.Assess(nil, nil)
	r.Assess(nil, nil)
	if len(r.Problems) != 1 {
		t.Errorf("problems = %v", r.Problems)
	}
}

func TestTheHealthReadIsOneReadPerAgentWithNoWait(t *testing.T) {
	fc, _ := servingCluster(t, agent("a", "n1"), agent("b", "n2"))
	fc.components = healthyComponents()
	slept := false
	c := &Collector{Cluster: fc, Now: newVirtualTime().Now, Sleep: func(context.Context, time.Duration) error { slept = true; return nil }}
	r, err := c.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !r.Healthy || slept || fc.scrapeCount("a") != 1 || fc.scrapeCount("b") != 1 {
		t.Errorf("healthy=%v slept=%v scrapes a=%d b=%d; --wait polls this, so it must be cheap",
			r.Healthy, slept, fc.scrapeCount("a"), fc.scrapeCount("b"))
	}
	if len(r.Workloads) != 0 {
		t.Errorf("a health read has no window, so it has no rates: %+v", r.Workloads)
	}
	fc.agentsErr = errors.New("pods is forbidden")
	if _, err := c.Health(context.Background()); err == nil {
		t.Error("a failed agent listing was not an error")
	}
}

func TestACollectIsAssessedToo(t *testing.T) {
	fc, _ := servingCluster(t, agent("a", "n1"))
	fc.components = healthyComponents()
	r, err := collectorOn(fc, newVirtualTime()).Collect(context.Background())
	if err != nil || !r.Healthy || len(r.Components) != 2 {
		t.Errorf("err=%v healthy=%v components=%+v", err, r.Healthy, r.Components)
	}
}

func TestTheTableLeadsWithTheVerdict(t *testing.T) {
	var healthy, broken bytes.Buffer
	r := okReport(t)
	r.Assess(healthyComponents(), nil)
	_ = RenderText(&healthy, r)
	if !strings.Contains(healthy.String(), "podtrace is healthy") || strings.Contains(healthy.String(), "PROBLEMS") ||
		!strings.Contains(healthy.String(), "COMPONENTS") || !strings.Contains(healthy.String(), "podtrace-operator  1/1") {
		t.Errorf("healthy output:\n%s", healthy.String())
	}
	r.Assess(nil, nil)
	_ = RenderText(&broken, r)
	if !strings.Contains(broken.String(), "podtrace is NOT healthy") || !strings.Contains(broken.String(), "✗ no podtrace operator found") {
		t.Errorf("unhealthy output:\n%s", broken.String())
	}
}

func deployment(name string, replicas *int32, available int32, labels map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "podtrace-system", Labels: labels},
		Spec:       appsv1.DeploymentSpec{Replicas: replicas},
		Status:     appsv1.DeploymentStatus{AvailableReplicas: available, UpdatedReplicas: available},
	}
}

func TestComponentsAreFoundByTheirLabels(t *testing.T) {
	operatorLabels := map[string]string{"app.kubernetes.io/name": "podtrace", "app.kubernetes.io/component": "operator"}
	two := int32(2)
	cs := fake.NewClientset(
		deployment("podtrace-operator", nil, 1, operatorLabels),
		deployment("podtrace-webhook", &two, 2, map[string]string{"app.kubernetes.io/name": "podtrace", "app.kubernetes.io/component": "webhook"}),
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: "podtrace-agent", Namespace: "podtrace-system",
				Labels: map[string]string{"podtrace.io/component": "agent", tracerConfigLabel: "default"}},
			Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 2, UpdatedNumberScheduled: 3},
		},
	)
	got, err := (&KubeCluster{Client: cs, SystemNamespace: "podtrace-system"}).Components(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("components = %+v, want the operator and the one fleet", got)
	}
	if got[0].Kind != KindOperator || got[0].Desired != 1 {
		t.Errorf("operator = %+v; a Deployment without replicas set has one", got[0])
	}
	if got[1].Kind != KindFleet || got[1].Fleet != "default" || got[1].Ready != 2 || got[1].Desired != 3 {
		t.Errorf("fleet = %+v", got[1])
	}
}

func TestAFailedComponentListIsReturned(t *testing.T) {
	for _, resource := range []string{"deployments", "daemonsets"} {
		cs := fake.NewClientset()
		cs.PrependReactor("list", resource, func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("forbidden")
		})
		if _, err := (&KubeCluster{Client: cs, SystemNamespace: "podtrace-system"}).Components(context.Background()); err == nil {
			t.Errorf("a failed %s list was not an error", resource)
		}
	}
}

func TestAnOperatorScaledOutIsCountedAtItsReplicas(t *testing.T) {
	two := int32(2)
	cs := fake.NewClientset(deployment("podtrace-operator", &two, 1,
		map[string]string{"app.kubernetes.io/name": "podtrace", "app.kubernetes.io/component": "operator"}))
	got, err := (&KubeCluster{Client: cs, SystemNamespace: "podtrace-system"}).Components(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Desired != 2 || got[0].Ready != 1 {
		t.Errorf("operator = %+v; one of two replicas available is a rollout still in progress", got)
	}
}

func TestAPodBeingDeletedIsNotAnAgent(t *testing.T) {
	gone := agentPod("old", "n1", false, 0, 9090)
	now := metav1.Now()
	gone.DeletionTimestamp = &now
	gone.Finalizers = []string{"test/keep"}
	cs := fake.NewClientset(gone, agentPod("new", "n1", true, 0, 9090))
	agents, err := (&KubeCluster{Client: cs, SystemNamespace: "podtrace-system"}).Agents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].Name != "new" {
		t.Errorf("agents = %+v; the pod being replaced in a rollout must not count", agents)
	}
}

func TestAStartingAgentIsNotReadyNotUnreachable(t *testing.T) {
	starting := agent("b", "n2")
	starting.Ready = false
	r := Build([]AgentScrape{
		{Agent: agent("a", "n1"), Window: window(t, newAgentMetrics(false), func() {})},
		{Agent: starting, Err: errors.New("the API server could not reach the agent")},
	}, nil, Options{}, t0)
	if r.Agents[1].State != StateNotReady || r.Agents[1].Reason != "" {
		t.Errorf("agent = %+v; a pod still starting cannot be reached, and that is not news", r.Agents[1])
	}
	if strings.Contains(strings.Join(r.Warnings, " "), "networkPolicy") {
		t.Errorf("warnings = %v; a starting pod says nothing about the network path", r.Warnings)
	}
}

func TestAFleetBetweenPodsIsNotReportedAsMissing(t *testing.T) {
	r := Build(nil, nil, Options{}, t0)
	r.Assess(healthyComponents(), nil)
	got := strings.Join(r.Problems, " ")
	if r.Healthy || !strings.Contains(got, "no agent pods are running yet") || strings.Contains(got, "installed") {
		t.Errorf("problems = %v; mid-rollout, with the fleet there and its pods being replaced, "+
			"telling the user to check the install misleads", r.Problems)
	}
}
