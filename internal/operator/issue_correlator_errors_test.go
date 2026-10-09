package operator

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

func failingCorrelator(t *testing.T, funcs interceptor.Funcs, objects ...client.Object) *IssueCorrelator {
	t.Helper()
	scheme, err := NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	c := &IssueCorrelator{
		Client:          fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithInterceptorFuncs(funcs).Build(),
		SystemNamespace: "podtrace-system",
		Logger:          logr.Discard(),
	}
	if err := c.Register(prometheus.NewRegistry()); err != nil {
		t.Fatal(err)
	}
	return c
}

func failListOf(target client.ObjectList) interceptor.Funcs {
	return interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		switch list.(type) {
		case *corev1.PodList:
			if _, ok := target.(*corev1.PodList); ok {
				return errors.New("pods unavailable")
			}
		case *discoveryv1.EndpointSliceList:
			if _, ok := target.(*discoveryv1.EndpointSliceList); ok {
				return errors.New("slices unavailable")
			}
		}
		return c.List(ctx, list, opts...)
	}}
}

func TestAnUnlistableFleetCorrelatesNothingRatherThanFailing(t *testing.T) {
	c := failingCorrelator(t, failListOf(&corev1.PodList{}))
	got := c.Correlate(context.Background())
	if got.AgentsRead != 0 || len(got.Issues) != 0 {
		t.Errorf("correlation %+v", got)
	}
	if _, ok := c.Latest(); !ok {
		t.Error("an empty pass was not published, so /correlations keeps serving a stale one")
	}
}

func TestAServiceThatCannotBeResolvedLinksNothing(t *testing.T) {
	a, b := newFakeAgent(t, frontNode), newFakeAgent(t, backendNode)
	c := failingCorrelator(t, failListOf(&discoveryv1.EndpointSliceList{}), a.pod("agent-a"), b.pod("agent-b"),
		deploymentPod("shop", "backend-7d8c9c-x1", "backend"), serviceSlice("shop", "backend", "backend-7d8c9c-x1"))
	if causes := causesOf(c.Correlate(context.Background()), detector.IDL7LatencyDegraded, "front"); len(causes) != 0 {
		t.Errorf("front blamed on %v", causes)
	}
}

func TestAnEndpointWhosePodIsGoneIsSkipped(t *testing.T) {
	a, b := newFakeAgent(t, frontNode), newFakeAgent(t, backendNode)
	c, _ := newCorrelator(t, a.pod("agent-a"), b.pod("agent-b"),
		deploymentPod("shop", "backend-7d8c9c-x1", "backend"),
		serviceSlice("shop", "backend", "backend-gone", "backend-7d8c9c-x1"))
	if causes := causesOf(c.Correlate(context.Background()), detector.IDL7LatencyDegraded, "front"); len(causes) != 1 {
		t.Errorf("front causes %v, want the one through the pod that exists", causes)
	}
}

func TestAServiceCalledByTwoWorkloadsIsResolvedOnce(t *testing.T) {
	gets := 0
	both := newFakeAgent(t, `{"issues":[
{"id":"l7.latency_degraded","namespace":"shop","workload":"front"},
{"id":"l7.latency_degraded","namespace":"shop","workload":"admin"},
{"id":"l7.latency_degraded","namespace":"shop","workload":"backend"}],
"edges":[{"namespace":"shop","workload":"front","targetNamespace":"shop","targetService":"backend","requests":1},
{"namespace":"shop","workload":"admin","targetNamespace":"shop","targetService":"backend","requests":1}]}`)
	c := failingCorrelator(t, interceptor.Funcs{Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		gets++
		return cl.Get(ctx, key, obj, opts...)
	}}, both.pod("agent-a"), deploymentPod("shop", "backend-7d8c9c-x1", "backend"), serviceSlice("shop", "backend", "backend-7d8c9c-x1"))
	got := c.Correlate(context.Background())
	if len(causesOf(got, detector.IDL7LatencyDegraded, "front")) != 1 || len(causesOf(got, detector.IDL7LatencyDegraded, "admin")) != 1 {
		t.Errorf("correlation %+v", got.Issues)
	}
	if gets != 1 {
		t.Errorf("the Service's pod was read %d times in one pass, want once", gets)
	}
}

func TestAnAgentWithAnUnusableAddressIsAFailedRead(t *testing.T) {
	a := newFakeAgent(t, backendNode)
	pod := a.pod("agent-a")
	pod.Status.PodIP = "bad host"
	c, _ := newCorrelator(t, pod)
	if got := c.Correlate(context.Background()); got.AgentsFailed != 1 {
		t.Errorf("failed %d, want 1", got.AgentsFailed)
	}
}

func TestRegisteringTheCorrelationTwiceIsAnError(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := (&IssueCorrelator{}).Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := (&IssueCorrelator{}).Register(reg); err == nil {
		t.Error("a second correlator registered over the first")
	}
}
