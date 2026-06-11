package kubernetes

import (
	"context"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestParseTarget_BracketedIPv6WithoutPort: "[::1]" used to panic with a
// slice out-of-range in the event hot path.
func TestParseTarget_BracketedIPv6WithoutPort(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port int
	}{
		{"[::1]", "::1", 0},
		{"[::1]:8080", "::1", 8080},
		{"[2001:db8::2]", "2001:db8::2", 0},
		{"10.0.0.1:443", "10.0.0.1", 443},
		{"10.0.0.1", "10.0.0.1", 0},
		{"", "", 0},
	}
	for _, c := range cases {
		ip, port := parseTarget(c.in)
		if ip != c.ip || port != c.port {
			t.Errorf("parseTarget(%q) = (%q, %d), want (%q, %d)", c.in, ip, port, c.ip, c.port)
		}
	}
}

// TestPickContainer_StatusOrderIndependent: ContainerStatuses is not
// guaranteed to share Spec.Containers' order; positional pairing returned
// the wrong container's ID and cgroup.
func TestPickContainer_StatusOrderIndependent(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "app"}, {Name: "sidecar"},
		}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "sidecar", ContainerID: "containerd://side"},
			{Name: "app", ContainerID: "containerd://app1"},
		}},
	}

	status, spec := pickContainer(pod, "")
	if status == nil || spec == nil {
		t.Fatal("expected the first spec container to resolve")
	}
	if status.Name != "app" || status.ContainerID != "containerd://app1" || spec.Name != "app" {
		t.Errorf("default pick = status %q/%s spec %q, want the app container", status.Name, status.ContainerID, spec.Name)
	}

	status, spec = pickContainer(pod, "sidecar")
	if status == nil || status.ContainerID != "containerd://side" || spec == nil || spec.Name != "sidecar" {
		t.Errorf("named pick mismatched: status %+v spec %+v", status, spec)
	}

	if status, _ := pickContainer(pod, "missing"); status != nil {
		t.Errorf("unknown container name must return nil status, got %+v", status)
	}
}

// TestCgroupV1Controllers parses the controller field of v1
// /proc/<pid>/cgroup lines, including the name= prefix form.
func TestCgroupV1Controllers(t *testing.T) {
	if got := cgroupV1Controllers("cpu,cpuacct"); len(got) != 2 || got[0] != "cpu" || got[1] != "cpuacct" {
		t.Errorf("cpu,cpuacct = %v", got)
	}
	if got := cgroupV1Controllers("name=systemd"); len(got) != 1 || got[0] != "systemd" {
		t.Errorf("name=systemd = %v", got)
	}
}

// TestServiceResolver_NegativeCacheSuppressesRelisting: a miss used to
// trigger a cluster-wide Endpoints list on EVERY lookup; the negative
// cache must absorb repeats.
func TestServiceResolver_NegativeCacheSuppressesRelisting(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	var mu sync.Mutex
	lists := 0
	clientset.PrependReactor("list", "endpoints", func(a k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		lists++
		mu.Unlock()
		return false, nil, nil
	})

	sr := NewServiceResolver(clientset)
	for i := 0; i < 5; i++ {
		if svc := sr.ResolveService(context.Background(), "10.9.9.9", 80); svc != nil {
			t.Fatalf("unexpected service for unbacked endpoint: %+v", svc)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if lists != 1 {
		t.Errorf("Endpoints listed %d times for 5 identical misses, want 1 (negative cache)", lists)
	}
}

// TestServiceResolver_BulkPopulatesFromSingleList: one list call must
// satisfy later lookups of OTHER endpoints from cache.
func TestServiceResolver_BulkPopulatesFromSingleList(t *testing.T) {
	mkEndpoints := func(name, ip string, port int32) *corev1.Endpoints { //nolint:staticcheck // Endpoints API still widely used
		return &corev1.Endpoints{ //nolint:staticcheck // Endpoints API still widely used
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Subsets: []corev1.EndpointSubset{{ //nolint:staticcheck // Endpoints API still widely used
				Addresses: []corev1.EndpointAddress{{IP: ip}},
				Ports:     []corev1.EndpointPort{{Port: port}},
			}},
		}
	}
	clientset := fake.NewSimpleClientset(
		mkEndpoints("svc-a", "10.0.0.1", 80),
		mkEndpoints("svc-b", "10.0.0.2", 443),
	)
	var mu sync.Mutex
	lists := 0
	clientset.PrependReactor("list", "endpoints", func(a k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		lists++
		mu.Unlock()
		return false, nil, nil
	})

	sr := NewServiceResolver(clientset)
	if svc := sr.ResolveService(context.Background(), "10.0.0.1", 80); svc == nil || svc.Name != "svc-a" {
		t.Fatalf("svc-a lookup = %+v", svc)
	}
	if svc := sr.ResolveService(context.Background(), "10.0.0.2", 443); svc == nil || svc.Name != "svc-b" {
		t.Fatalf("svc-b lookup = %+v", svc)
	}

	mu.Lock()
	defer mu.Unlock()
	if lists != 1 {
		t.Errorf("Endpoints listed %d times, want 1 (second lookup served from bulk-populated cache)", lists)
	}
}

// TestChannelTargetSource_PublishCloseRace: Publish racing Close used to
// send on a closed channel and panic. Run under -race.
func TestChannelTargetSource_PublishCloseRace(t *testing.T) {
	for i := 0; i < 50; i++ {
		s := NewChannelTargetSource()
		_ = s.Start(context.Background())
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				s.Publish([]*PodInfo{{PodName: "p"}})
			}
		}()
		go func() {
			defer wg.Done()
			s.Close()
		}()
		wg.Wait()
		s.Close()
		s.Publish(nil)
	}
}

// TestEventsCorrelator_RewatchAfterServerClose: API servers close watches
// after a few minutes; the correlator must re-establish the watch instead
// of silently collecting nothing for the rest of the trace.
func TestEventsCorrelator_RewatchAfterServerClose(t *testing.T) {
	saved := rewatchBackoff
	rewatchBackoff = 10 * time.Millisecond
	defer func() { rewatchBackoff = saved }()

	clientset := fake.NewSimpleClientset()
	var mu sync.Mutex
	var watchers []*watch.FakeWatcher
	clientset.PrependWatchReactor("events", func(k8stesting.Action) (bool, watch.Interface, error) {
		w := watch.NewFake()
		mu.Lock()
		watchers = append(watchers, w)
		mu.Unlock()
		return true, w, nil
	})

	ec := NewEventsCorrelator(clientset, "pod-x", "default")
	if err := ec.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer ec.Stop()

	mu.Lock()
	first := watchers[0]
	mu.Unlock()
	first.Stop()

	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := len(watchers)
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("watch was never re-established after server-side close")
		case <-time.After(10 * time.Millisecond):
		}
	}

	mu.Lock()
	second := watchers[1]
	mu.Unlock()
	second.Add(&corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "ev1", Namespace: "default"},
		InvolvedObject: corev1.ObjectReference{Name: "pod-x"},
		Reason:         "AfterRewatch",
	})
	deadline = time.After(5 * time.Second)
	for {
		evs := ec.GetEvents()
		if len(evs) == 1 && evs[0].Reason == "AfterRewatch" {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("event after re-watch never collected, have %d", len(evs))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestEventsCorrelator_StopIdempotent: a second Stop used to panic on the
// already-closed channel.
func TestEventsCorrelator_StopIdempotent(t *testing.T) {
	ec := NewEventsCorrelator(fake.NewSimpleClientset(), "p", "default")
	if err := ec.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ec.Stop()
	ec.Stop()
}

// TestTargetRegistry_DropsStaleTargetOnRestart: when a pod's container
// restarts, resolution of the new container can fail transiently, but the
// cached entry points at the OLD container's dead cgroup and must be
// dropped, not served indefinitely.
func TestTargetRegistry_DropsStaleTargetOnRestart(t *testing.T) {
	t.Setenv("PODTRACE_CRI_RESOLVE", "false")
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	uid := types.UID("u1")
	tr.targets[uid] = &PodInfo{PodName: "p", ContainerID: "oldcontainer1234"}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: uid, Name: "p", Namespace: "ns"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main"}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "main", ContainerID: "containerd://deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
		}},
	}
	tr.handlePodUpsert(context.Background(), pod)

	if _, ok := tr.targets[uid]; ok {
		t.Error("stale target (old container ID) must be dropped when the pod no longer runs that container")
	}
}
