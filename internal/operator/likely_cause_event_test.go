package operator

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/gma1k/podtrace/internal/alerting"
)

const frontNodeWithPod = `{"issues":[{"id":"l7.latency_degraded","namespace":"shop","workload":"front","pod":"front-0"}],
"edges":[{"namespace":"shop","workload":"front","targetNamespace":"shop","targetService":"backend","requests":12}]}`

func announcingCorrelator(t *testing.T, funcs interceptor.Funcs, objects ...client.Object) (*IssueCorrelator, client.Client) {
	t.Helper()
	scheme, err := NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithInterceptorFuncs(funcs).Build()
	c := &IssueCorrelator{Client: cl, Writer: cl, SystemNamespace: "podtrace-system", Logger: logr.Discard()}
	if err := c.Register(prometheus.NewRegistry()); err != nil {
		t.Fatal(err)
	}
	return c, cl
}

func causeEvents(t *testing.T, cl client.Client) []corev1.Event {
	t.Helper()
	var list corev1.EventList
	if err := cl.List(context.Background(), &list, client.InNamespace("shop")); err != nil {
		t.Fatal(err)
	}
	var out []corev1.Event
	for _, e := range list.Items {
		if e.Reason == EventReasonLikelyCause {
			out = append(out, e)
		}
	}
	return out
}

func frontPod() *corev1.Pod {
	p := deploymentPod("shop", "front-0", "front")
	p.UID = "front-0-uid"
	return p
}

func backendCluster(front, back *fakeAgent) []client.Object {
	return []client.Object{front.pod("agent-a"), back.pod("agent-b"), frontPod(),
		deploymentPod("shop", "backend-7d8c9c-x1", "backend"), serviceSlice("shop", "backend", "backend-7d8c9c-x1")}
}

func backendOnly(front, back *fakeAgent) []client.Object {
	return []client.Object{front.pod("agent-a"), back.pod("agent-b"),
		deploymentPod("shop", "backend-7d8c9c-x1", "backend"), serviceSlice("shop", "backend", "backend-7d8c9c-x1")}
}

func TestACauseOnAnotherWorkloadIsAnnouncedOnTheAffectedPod(t *testing.T) {
	front, back := newFakeAgent(t, frontNodeWithPod), newFakeAgent(t, backendNode)
	c, cl := announcingCorrelator(t, interceptor.Funcs{}, backendCluster(front, back)...)
	c.Correlate(context.Background())

	events := causeEvents(t, cl)
	if len(events) != 1 {
		t.Fatalf("%d likely-cause Events, want 1", len(events))
	}
	e := events[0]
	causes := "db.pool_saturated on shop/backend, through l7.latency_degraded on shop/backend"
	if e.InvolvedObject.Name != "front-0" || e.InvolvedObject.Kind != "Pod" {
		t.Errorf("involved object %+v, want the pod the agent named", e.InvolvedObject)
	}
	if e.InvolvedObject.UID != "front-0-uid" || e.InvolvedObject.APIVersion != "v1" {
		t.Errorf("involved object %+v: without the pod's UID kubectl describe never lists the Event", e.InvolvedObject)
	}
	if want := "l7.latency_degraded on shop/front: likely cause " + causes; e.Message != want {
		t.Errorf("message %q, want %q", e.Message, want)
	}
	if e.Annotations[alerting.AnnotationLikelyCauses] != causes || e.Annotations[alerting.AnnotationIssueID] != "l7.latency_degraded" ||
		e.Annotations[alerting.AnnotationWorkload] != "front" {
		t.Errorf("annotations %v", e.Annotations)
	}
	if e.Reason == alerting.EventReasonAlert {
		t.Error("the Event uses the alert reason, so it would start a session")
	}
}

func TestALinkIsAnnouncedOnceWhileItHolds(t *testing.T) {
	front, back := newFakeAgent(t, frontNodeWithPod), newFakeAgent(t, backendNode)
	c, cl := announcingCorrelator(t, interceptor.Funcs{}, backendCluster(front, back)...)
	for i := 0; i < 3; i++ {
		c.Correlate(context.Background())
	}
	if n := len(causeEvents(t, cl)); n != 1 {
		t.Errorf("%d Events over three passes, want 1", n)
	}
}

func TestALinkThatReturnsIsAnnouncedAgain(t *testing.T) {
	front, back := newFakeAgent(t, frontNodeWithPod), newFakeAgent(t, backendNode)
	c, cl := announcingCorrelator(t, interceptor.Funcs{}, backendCluster(front, back)...)
	c.Correlate(context.Background())
	back.body = `{"issues":[],"edges":[]}`
	c.Correlate(context.Background())
	back.body = backendNode
	c.Correlate(context.Background())
	if n := len(causeEvents(t, cl)); n != 2 {
		t.Errorf("%d Events, want one per appearance", n)
	}
}

func TestACauseOnTheSameWorkloadIsLeftToTheAgentsEvent(t *testing.T) {
	back := newFakeAgent(t, backendNode)
	c, cl := announcingCorrelator(t, interceptor.Funcs{}, back.pod("agent-b"), deploymentPod("shop", "backend-7d8c9c-x1", "backend"))
	c.Correlate(context.Background())
	if n := len(causeEvents(t, cl)); n != 0 {
		t.Errorf("%d Events for same-workload causes the agent already reports", n)
	}
}

func TestAWorkloadIssueWithoutAPodIsAnnouncedOnOneOfItsPods(t *testing.T) {
	front, back := newFakeAgent(t, frontNode), newFakeAgent(t, backendNode)
	objects := append(backendOnly(front, back),
		deploymentPod("shop", "front-7d8c9c-b", "front"), deploymentPod("shop", "front-7d8c9c-a", "front"))
	c, cl := announcingCorrelator(t, interceptor.Funcs{}, objects...)
	c.Correlate(context.Background())
	events := causeEvents(t, cl)
	if len(events) != 1 || events[0].InvolvedObject.Name != "front-7d8c9c-a" {
		t.Errorf("events %+v, want one on the first pod of front by name", events)
	}
}

func TestNoPodOfTheWorkloadMeansNoEvent(t *testing.T) {
	front, back := newFakeAgent(t, frontNode), newFakeAgent(t, backendNode)
	c, cl := announcingCorrelator(t, interceptor.Funcs{}, backendOnly(front, back)...)
	c.Correlate(context.Background())
	if n := len(causeEvents(t, cl)); n != 0 {
		t.Errorf("%d Events with no pod to put them on", n)
	}
}

func TestAnUnlistablePodCacheMeansNoEvent(t *testing.T) {
	front, back := newFakeAgent(t, frontNode), newFakeAgent(t, backendNode)
	failShopPods := interceptor.Funcs{List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		lo := &client.ListOptions{}
		lo.ApplyOptions(opts)
		if _, ok := list.(*corev1.PodList); ok && lo.Namespace == "shop" {
			return errors.New("pods unavailable")
		}
		return cl.List(ctx, list, opts...)
	}}
	c, cl := announcingCorrelator(t, failShopPods, backendOnly(front, back)...)
	c.Correlate(context.Background())
	if n := len(causeEvents(t, cl)); n != 0 {
		t.Errorf("%d Events", n)
	}
}

func TestAFailedEventWriteIsRetriedOnTheNextPass(t *testing.T) {
	front, back := newFakeAgent(t, frontNodeWithPod), newFakeAgent(t, backendNode)
	fail := true
	c, cl := announcingCorrelator(t, interceptor.Funcs{Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if _, ok := obj.(*corev1.Event); ok && fail {
			return errors.New("api server unavailable")
		}
		return cl.Create(ctx, obj, opts...)
	}}, backendCluster(front, back)...)
	c.Correlate(context.Background())
	if n := len(causeEvents(t, cl)); n != 0 {
		t.Fatalf("%d Events though the write failed", n)
	}
	fail = false
	c.Correlate(context.Background())
	if n := len(causeEvents(t, cl)); n != 1 {
		t.Errorf("%d Events after the retry, want 1", n)
	}
}

func TestWithoutAWriterNothingIsAnnounced(t *testing.T) {
	front, back := newFakeAgent(t, frontNodeWithPod), newFakeAgent(t, backendNode)
	c, _ := newCorrelator(t, backendCluster(front, back)...)
	if got := c.Correlate(context.Background()); len(got.Issues) == 0 {
		t.Error("the correlation itself stopped working without a writer")
	}
}

func TestATerminatingPodIsNotChosenForTheEvent(t *testing.T) {
	front, back := newFakeAgent(t, frontNode), newFakeAgent(t, backendNode)
	leaving := deploymentPod("shop", "front-7d8c9c-a", "front")
	now := metav1.Now()
	leaving.DeletionTimestamp = &now
	leaving.Finalizers = []string{"podtrace.io/test"}
	objects := append(backendOnly(front, back), leaving, deploymentPod("shop", "front-7d8c9c-b", "front"))
	c, cl := announcingCorrelator(t, interceptor.Funcs{}, objects...)
	c.Correlate(context.Background())
	events := causeEvents(t, cl)
	if len(events) != 1 || events[0].InvolvedObject.Name != "front-7d8c9c-b" {
		t.Errorf("events %+v, want one on the pod that is not terminating", events)
	}
}

func TestAPodTheAgentNamedThatIsGoneFallsBackToALivePod(t *testing.T) {
	front, back := newFakeAgent(t, frontNodeWithPod), newFakeAgent(t, backendNode)
	objects := append(backendOnly(front, back), deploymentPod("shop", "front-7d8c9c-a", "front"))
	c, cl := announcingCorrelator(t, interceptor.Funcs{}, objects...)
	c.Correlate(context.Background())
	events := causeEvents(t, cl)
	if len(events) != 1 || events[0].InvolvedObject.Name != "front-7d8c9c-a" {
		t.Errorf("events %+v, want one on a pod that exists", events)
	}
}
