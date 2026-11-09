package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func ipPod(ns, name, ip string, phase corev1.PodPhase, hostNetwork bool) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{"app": name}},
		Spec:       corev1.PodSpec{HostNetwork: hostNetwork},
		Status:     corev1.PodStatus{Phase: phase, PodIP: ip, PodIPs: []corev1.PodIP{{IP: ip}}},
	}
}

func TestPickPodForIP(t *testing.T) {
	running := ipPod("team-a", "web", "10.0.0.5", corev1.PodRunning, false)
	pending := ipPod("team-a", "web-new", "10.0.0.5", corev1.PodPending, false)
	done := ipPod("tenant-b", "nightly-job", "10.0.0.5", corev1.PodSucceeded, false)
	failed := ipPod("tenant-c", "batch", "10.0.0.5", corev1.PodFailed, false)
	host1 := ipPod("kube-system", "kube-proxy", "172.18.0.2", corev1.PodRunning, true)
	host2 := ipPod("monitoring", "node-exporter", "172.18.0.2", corev1.PodRunning, true)

	cases := []struct {
		name       string
		candidates []*corev1.Pod
		want       *corev1.Pod
	}{
		{"none", nil, nil},
		{"single running", []*corev1.Pod{running}, running},
		{"completed job before the running owner", []*corev1.Pod{done, running}, running},
		{"failed and completed before a pending owner", []*corev1.Pod{failed, done, pending}, pending},
		{"only a finished pod", []*corev1.Pod{done}, done},
		{"two finished pods are ambiguous", []*corev1.Pod{done, failed}, nil},
		{"one hostNetwork pod", []*corev1.Pod{host1}, host1},
		{"several hostNetwork pods are ambiguous", []*corev1.Pod{host1, host2}, nil},
		{"pod network beats hostNetwork", []*corev1.Pod{host1, running}, running},
		{"two live owners are ambiguous", []*corev1.Pod{running, pending}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pickPodForIP(tc.candidates); got != tc.want {
				t.Fatalf("pickPodForIP = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTrimPodForCacheKeepsPhaseAndHostNetwork(t *testing.T) {
	out, _ := trimPodForCache(ipPod("ns", "p", "10.0.0.9", corev1.PodSucceeded, true))
	got := out.(*corev1.Pod)
	if got.Status.Phase != corev1.PodSucceeded || !got.Spec.HostNetwork {
		t.Fatalf("phase=%q hostNetwork=%v, want Succeeded/true", got.Status.Phase, got.Spec.HostNetwork)
	}
}

func startedInformerCache(t *testing.T, cs *fake.Clientset) *InformerCache {
	t.Helper()
	t.Setenv("PODTRACE_K8S_USE_INFORMERS", "true")
	ic := NewInformerCache(cs)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { ic.Stop(); cancel() })
	ic.Start(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for !ic.PodsSynced() {
		if time.Now().After(deadline) {
			t.Fatal("pod informer did not sync")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return ic
}

func TestInformerLookupNamesTheRunningOwnerNotAFinishedJobPod(t *testing.T) {
	cs := fake.NewSimpleClientset(
		ipPod("tenant-b", "nightly-job", "10.0.0.5", corev1.PodSucceeded, false),
		ipPod("team-a", "web", "10.0.0.5", corev1.PodRunning, false),
	)
	ic := startedInformerCache(t, cs)
	got := ic.GetPodByIP("10.0.0.5")
	if got == nil || got.Namespace != "team-a" || got.Name != "web" {
		t.Fatalf("GetPodByIP = %+v, want team-a/web", got)
	}
}

func TestInformerIndexesTheSecondaryFamilyAddress(t *testing.T) {
	pod := ipPod("team-a", "dual", "10.0.0.7", corev1.PodRunning, false)
	pod.Status.PodIPs = append(pod.Status.PodIPs, corev1.PodIP{IP: "fd00::7"})
	ic := startedInformerCache(t, fake.NewSimpleClientset(pod))
	got := ic.GetPodByIP("fd00::7")
	if got == nil || got.Name != "dual" || got.IP != "fd00::7" {
		t.Fatalf("GetPodByIP(fd00::7) = %+v, want team-a/dual", got)
	}
}

func TestASyncedInformerMissDoesNotListPods(t *testing.T) {
	cs := fake.NewSimpleClientset()
	ic := startedInformerCache(t, cs)
	var lists int32
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		atomic.AddInt32(&lists, 1)
		return true, &corev1.PodList{}, nil
	})
	ce := &ContextEnricher{clientset: cs, podCache: newPodIPCache(maxPodIPCacheEntries), cacheTTL: time.Minute, informerCache: ic}
	for i := 0; i < 50; i++ {
		if got := ce.resolvePodByIP(context.Background(), fmt.Sprintf("10.9.0.%d", i)); got != nil {
			t.Fatalf("unexpected pod %+v", got)
		}
	}
	if n := atomic.LoadInt32(&lists); n != 0 {
		t.Fatalf("a synced informer is authoritative; got %d cluster-wide pod LISTs", n)
	}
	if n := ce.podCache.Len(); n != 0 {
		t.Fatalf("pod cache holds %d entries, want none when the informer answers", n)
	}
}

func TestFallbackListPicksTheRunningOwner(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.PodList{Items: []corev1.Pod{
			*ipPod("tenant-b", "nightly-job", "10.0.0.5", corev1.PodSucceeded, false),
			*ipPod("team-a", "web", "10.0.0.5", corev1.PodRunning, false),
		}}, nil
	})
	ce := &ContextEnricher{clientset: cs}
	got := ce.fetchPodByIP(context.Background(), "10.0.0.5")
	if got == nil || got.Namespace != "team-a" {
		t.Fatalf("fetchPodByIP = %+v, want team-a/web", got)
	}
}

func TestAForbiddenPodListIsNotRetried(t *testing.T) {
	t.Setenv("PODTRACE_K8S_USE_INFORMERS", "false")
	cs := fake.NewSimpleClientset()
	var lists int32
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		atomic.AddInt32(&lists, 1)
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("rbac"))
	})
	ce := NewContextEnricher(cs, &PodInfo{Namespace: "src"})
	for i := 0; i < 20; i++ {
		ce.resolvePodByIP(context.Background(), fmt.Sprintf("10.8.0.%d", i))
	}
	if n := atomic.LoadInt32(&lists); n != 1 {
		t.Fatalf("pod LISTs = %d, want 1: a refused LIST is refused every time", n)
	}
}

func TestPodIPCacheStaysBounded(t *testing.T) {
	c := newPodIPCache(8)
	now := time.Now()
	for i := 0; i < 100; i++ {
		c.Store(fmt.Sprintf("10.0.0.%d", i), &cacheEntry{expiresAt: now.Add(time.Duration(i) * time.Second)})
	}
	if n := c.Len(); n != 8 {
		t.Fatalf("cache holds %d entries, want 8", n)
	}
	if _, ok := c.Load("10.0.0.99"); !ok {
		t.Fatal("the newest entry was evicted")
	}
	if _, ok := c.Load("10.0.0.0"); ok {
		t.Fatal("the entry closest to expiry survived")
	}
}

func TestPodIPCachePrefersEvictingExpiredEntries(t *testing.T) {
	c := newPodIPCache(3)
	now := time.Now()
	c.Store("keep-1", &cacheEntry{expiresAt: now.Add(time.Hour)})
	c.Store("stale", &cacheEntry{expiresAt: now.Add(-time.Second)})
	c.Store("keep-2", &cacheEntry{expiresAt: now.Add(time.Hour)})
	c.Store("new", &cacheEntry{expiresAt: now.Add(time.Hour)})
	for _, ip := range []string{"keep-1", "keep-2", "new"} {
		if _, ok := c.Load(ip); !ok {
			t.Errorf("%s was evicted, want the expired entry dropped instead", ip)
		}
	}
	c.Store("new", &cacheEntry{expiresAt: now.Add(2 * time.Hour)})
	if n := c.Len(); n != 3 {
		t.Fatalf("overwriting a key changed the size to %d", n)
	}
	visited := 0
	c.Range(func(string, *cacheEntry) bool { visited++; return false })
	if visited != 1 {
		t.Fatalf("Range visited %d entries after returning false, want 1", visited)
	}
}

func TestServiceResolutionFallsBackToTheAPIWithInformersDisabled(t *testing.T) {
	t.Setenv("PODTRACE_K8S_USE_INFORMERS", "false")
	cs := fake.NewSimpleClientset()
	var lists int32
	cs.PrependReactor("list", "endpoints", func(k8stesting.Action) (bool, runtime.Object, error) {
		atomic.AddInt32(&lists, 1)
		return true, nil, errors.New("stop here")
	})
	ce := NewContextEnricher(cs, &PodInfo{Namespace: "src"})
	ce.Start(context.Background())
	defer ce.Stop()
	ce.serviceResolver.ResolveService(context.Background(), "10.0.0.5", 8080)
	if n := atomic.LoadInt32(&lists); n != 1 {
		t.Fatalf("Endpoints LISTs = %d, want 1: with informers disabled the API is the only source of service names", n)
	}
}

func TestPodsSyncedIsFalseBeforeStart(t *testing.T) {
	var nilCache *InformerCache
	if nilCache.PodsSynced() {
		t.Error("a nil cache is never synced")
	}
	if NewInformerCache(fake.NewSimpleClientset()).PodsSynced() {
		t.Error("an unstarted cache is not synced")
	}
}
