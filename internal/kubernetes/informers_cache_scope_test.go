package kubernetes

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

func forbidListOutside(cs *fake.Clientset, resource string, allowed ...string) *[]string {
	var listed []string
	cs.PrependReactor("list", resource, func(a k8stesting.Action) (bool, runtime.Object, error) {
		ns := a.GetNamespace()
		listed = append(listed, ns)
		for _, ok := range allowed {
			if ns == ok {
				return false, nil, nil
			}
		}
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: resource}, "", errors.New("rbac"))
	})
	return &listed
}

func peerPod(ns, name, ip string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{"app": name}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip},
	}
}

func peerSlice(ns, service, ip string, port int32) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: service + "-x", Labels: map[string]string{discoveryv1.LabelServiceName: service}},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{ip}}},
		Ports:      []discoveryv1.EndpointPort{{Port: &port}},
	}
}

func startScoped(t *testing.T, cs *fake.Clientset, namespaces ...string) *InformerCache {
	t.Helper()
	t.Setenv("PODTRACE_K8S_USE_INFORMERS", "true")
	t.Setenv("PODTRACE_K8S_INFORMERS_SYNC_TIMEOUT_SEC", "5")
	ic := NewScopedInformerCache(cs, namespaces)
	ic.Start(context.Background())
	t.Cleanup(ic.Stop)
	return ic
}

func TestANamespacedIdentityEnrichesPeersInItsTargetNamespaces(t *testing.T) {
	cs := fake.NewClientset(
		peerPod("shop", "api", "10.0.0.1"),
		peerPod("billing", "ledger", "10.0.0.2"),
		peerPod("secret", "vault", "10.0.0.3"),
		peerSlice("shop", "api", "10.0.0.1", 80),
		peerSlice("billing", "ledger", "10.0.0.2", 80),
	)
	podLists := forbidListOutside(cs, "pods", "shop", "billing")
	forbidListOutside(cs, "endpointslices", "shop", "billing")
	ic := startScoped(t, cs, "shop", "billing", "shop", "")

	if got := len(ic.podInformers()); got != 2 {
		t.Fatalf("pod informers = %d, want one per listable namespace", got)
	}
	if !ic.PodsSynced() || !ic.servicesActive() {
		t.Fatal("namespace-scoped informers must sync and answer lookups")
	}
	if pod := ic.GetPodByIP("10.0.0.2"); pod == nil || pod.Name != "ledger" {
		t.Fatalf("pod by IP in the second namespace = %+v", pod)
	}
	if pod := ic.GetPodByIP("10.0.0.3"); pod != nil {
		t.Fatalf("a pod outside the target namespaces resolved: %+v", pod)
	}
	if svc := ic.GetServiceByEndpoint("10.0.0.2", 80); svc == nil || svc.Name != "ledger" || svc.Namespace != "billing" {
		t.Fatalf("service in the second namespace = %+v", svc)
	}
	if svc := ic.GetServiceByEndpoint("10.0.0.9", 80); svc != nil {
		t.Fatalf("an unknown endpoint resolved: %+v", svc)
	}
	if (*podLists)[0] != metav1.NamespaceAll {
		t.Fatalf("first pod LIST went to %q, want a cluster-wide probe first", (*podLists)[0])
	}
}

func TestAnIdentityThatMayListClusterWideKeepsOneClusterWideInformer(t *testing.T) {
	cs := fake.NewClientset(peerPod("secret", "vault", "10.0.0.3"))
	ic := startScoped(t, cs, "shop")
	if got := len(ic.podInformers()); got != 1 {
		t.Fatalf("pod informers = %d, want one cluster-wide", got)
	}
	if pod := ic.GetPodByIP("10.0.0.3"); pod == nil {
		t.Fatal("a cluster-wide informer must see every namespace")
	}
}

func TestATransientProbeErrorKeepsTheClusterWideWatch(t *testing.T) {
	cs := fake.NewClientset()
	probed := false
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		if !probed {
			probed = true
			return true, nil, errors.New("apiserver busy")
		}
		return false, nil, nil
	})
	ic := NewScopedInformerCache(cs, []string{"shop"})
	scopes := ic.listableScopes(context.Background(), func(ns string) error {
		_, err := cs.CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{Limit: 1})
		return err
	})
	if len(scopes) != 1 || scopes[0] != metav1.NamespaceAll {
		t.Fatalf("scopes = %q, want the cluster-wide watch kept", scopes)
	}
}

func TestAnIdentityThatMayListNothingStartsNoInformerAndFallsBack(t *testing.T) {
	cs := fake.NewClientset()
	forbidListOutside(cs, "pods")
	forbidListOutside(cs, "endpointslices")
	ic := startScoped(t, cs, "shop")
	if len(ic.podInformers()) != 0 || len(ic.endpointSliceInformers()) != 0 {
		t.Fatal("no informer may start where every LIST is forbidden")
	}
	if ic.PodsSynced() {
		t.Fatal("no informer means no authoritative pod view")
	}
	if ic.servicesActive() {
		t.Fatal("with no EndpointSlice informer the resolver must use its own listing")
	}
}

func TestServiceLookupsWaitForTheInformersInsteadOfListing(t *testing.T) {
	t.Setenv("PODTRACE_K8S_USE_INFORMERS", "true")
	ic := NewInformerCache(fake.NewClientset())
	if !ic.servicesActive() {
		t.Fatal("an informer cache that has not started yet still owns service lookups")
	}
	var nilCache *InformerCache
	if nilCache.servicesActive() || nilCache.PodsSynced() {
		t.Fatal("a nil cache answers nothing")
	}
}

func TestAllSyncedNeedsEveryInformer(t *testing.T) {
	if allSynced(nil) {
		t.Fatal("no informers is not synced")
	}
	synced := syncedInformer{synced: true}
	if !allSynced([]cache.SharedIndexInformer{synced, synced}) {
		t.Fatal("all synced informers are synced")
	}
	if allSynced([]cache.SharedIndexInformer{synced, syncedInformer{}}) {
		t.Fatal("one unsynced informer makes the set unsynced")
	}
}

type syncedInformer struct {
	cache.SharedIndexInformer
	synced bool
}

func (s syncedInformer) HasSynced() bool { return s.synced }

func TestScopedEnricherNamesPeersInATargetNamespace(t *testing.T) {
	t.Setenv("PODTRACE_K8S_USE_INFORMERS", "true")
	t.Setenv("PODTRACE_K8S_INFORMERS_SYNC_TIMEOUT_SEC", "5")
	cs := fake.NewClientset(peerPod("shop", "api", "10.0.0.1"))
	forbidListOutside(cs, "pods", "shop")
	forbidListOutside(cs, "endpointslices", "shop")
	ce := NewScopedContextEnricher(cs, &PodInfo{Namespace: "shop"}, []string{"shop"})
	ce.Start(context.Background())
	defer ce.Stop()

	deadline := time.Now().Add(5 * time.Second)
	for !ce.informerCache.PodsSynced() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if pod := ce.resolvePodByIP(context.Background(), "10.0.0.1"); pod == nil || pod.Name != "api" {
		t.Fatalf("peer = %+v, want the pod in the target namespace", pod)
	}
}

func TestIndexersIgnoreObjectsOfTheWrongType(t *testing.T) {
	for name, index := range map[string]cache.IndexFunc{
		"pod ips":                indexPodIPs,
		"endpoint slice ips":     indexEndpointSliceIPs,
		"endpoint slice ip:port": indexEndpointSliceIPPorts,
	} {
		if keys, err := index("not an object"); keys != nil || err != nil {
			t.Errorf("%s indexed a foreign object: %v %v", name, keys, err)
		}
	}
}

type unindexedInformer struct {
	cache.SharedIndexInformer
}

func (unindexedInformer) GetIndexer() cache.Indexer {
	return cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
}

func TestGetPodByIPSkipsAnInformerWithoutTheIPIndex(t *testing.T) {
	ic := NewInformerCache(fake.NewClientset())
	ic.podInfs = []cache.SharedIndexInformer{unindexedInformer{}}
	if pod := ic.GetPodByIP("10.0.0.1"); pod != nil {
		t.Fatalf("pod = %+v, want a miss", pod)
	}
}
