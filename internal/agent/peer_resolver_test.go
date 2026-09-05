package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gma1k/podtrace/internal/workloadmetrics"
)

type failingReader struct {
	client.Client
}

func (failingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("cache not synced")
}

func staticPeers(byIP map[string]PeerIdentity) func(string, uint16) (PeerIdentity, bool) {
	return func(ip string, _ uint16) (PeerIdentity, bool) {
		identity, ok := byIP[ip]
		return identity, ok
	}
}

func TestAResolvedPeerIsNamedByItsService(t *testing.T) {
	r := NewPeerResolver(staticPeers(map[string]PeerIdentity{
		"10.244.1.7": {Service: "checkout", Namespace: "shop"},
	}))

	identity, ok := r.Resolve("10.244.1.7", 8080)
	if !ok {
		t.Fatal("Resolve reported no edge for an address that resolves")
	}
	if identity.Service != "checkout" || identity.Namespace != "shop" {
		t.Errorf("identity = %+v, want checkout/shop", identity)
	}
}

func TestAnEventWithNoPeerHasNoEdge(t *testing.T) {
	r := NewPeerResolver(staticPeers(nil))
	if _, ok := r.Resolve("", 8080); ok {
		t.Error("an empty peer address produced an edge; there is no far end to name")
	}

	var nilResolver *PeerResolver
	if _, ok := nilResolver.Resolve("10.0.0.1", 8080); ok {
		t.Error("a nil resolver produced an edge")
	}
}

func TestOnlyDrawableFarEndsProduceAnEdge(t *testing.T) {
	r := NewPeerResolver(staticPeers(nil))

	clusterLocal := []string{"10.244.3.9", "172.16.0.4", "192.168.5.5", "127.0.0.1", "fd00::1"}
	for _, ip := range clusterLocal {
		if identity, ok := r.Resolve(ip, 41234); ok {
			t.Errorf("%s produced an edge to %q. A cluster-local address matching no Service "+
				"endpoint is either the client half of a call already recorded from the other "+
				"end, or a peer podtrace cannot name — and collapsing every such peer into one "+
				"graph node merges unrelated systems into a single lie", ip, identity.Service)
		}
	}

	external := []string{"93.184.6.34", "2606:2800::1", "8.8.8.8"}
	for _, ip := range external {
		identity, ok := r.Resolve(ip, 443)
		if !ok {
			t.Errorf("%s produced no edge; traffic leaving the cluster is a real destination", ip)
			continue
		}
		if identity.Service != PeerExternal {
			t.Errorf("%s resolved to %q, want %q", ip, identity.Service, PeerExternal)
		}
		if identity.Namespace != "" {
			t.Errorf("%s carried namespace %q; traffic leaving the cluster has none",
				ip, identity.Namespace)
		}
	}
}

func TestTheReverseEdgeIsNotDrawn(t *testing.T) {
	// payments:8080 is a Service endpoint; the client's ephemeral port is not.
	r := NewPeerResolver(func(ip string, port uint16) (PeerIdentity, bool) {
		if ip == "10.244.1.7" && port == 8080 {
			return PeerIdentity{Service: "payments", Namespace: "shop"}, true
		}
		return PeerIdentity{}, false
	})

	forward, ok := r.Resolve("10.244.1.7", 8080)
	if !ok || forward.Service != "payments" {
		t.Fatalf("the client-side call resolved to %+v (ok=%v), want payments", forward, ok)
	}

	if _, ok := r.Resolve("10.244.2.4", 41234); ok {
		t.Error("the server side of the same call also drew an edge. Both halves would then " +
			"count the same request, and sum by (workload, target_service) over the edge " +
			"counter would report double the real rate")
	}
}

func TestResolutionIsCachedRatherThanRepeated(t *testing.T) {
	var calls int
	r := NewPeerResolver(func(string, uint16) (PeerIdentity, bool) {
		calls++
		return PeerIdentity{Service: "checkout", Namespace: "shop"}, true
	})

	for i := 0; i < 50; i++ {
		r.Resolve("10.244.1.7", 8080)
	}
	if calls != 1 {
		t.Errorf("the uncached lookup ran %d times for one address, want 1. Export is the hot "+
			"path — 150k events a minute were measured on a three-node cluster — so a lookup "+
			"per event would put an index query in front of every observation", calls)
	}
}

func TestAStaleResolutionExpires(t *testing.T) {
	clock := time.Now()
	var calls int
	r := NewPeerResolver(func(string, uint16) (PeerIdentity, bool) {
		calls++
		return PeerIdentity{Service: fmt.Sprintf("svc-%d", calls), Namespace: "shop"}, true
	})
	r.now = func() time.Time { return clock }

	first, _ := r.Resolve("10.244.1.7", 8080)
	clock = clock.Add(peerCacheTTL + time.Second)
	second, _ := r.Resolve("10.244.1.7", 8080)

	if first.Service == second.Service {
		t.Error("the resolution never expired. Endpoints move when a Deployment rolls, and a " +
			"stale answer attributes traffic to the workload that used to own the address")
	}
}

func TestAMissIsRetriedSoonerThanAHit(t *testing.T) {
	if peerNegativeCacheTTL >= peerCacheTTL {
		t.Fatalf("negative TTL %v is not shorter than the positive TTL %v. A miss is often a "+
			"race with an EndpointSlice that has not reached this agent yet, and retrying "+
			"sooner turns unresolved back into a name", peerNegativeCacheTTL, peerCacheTTL)
	}

	clock := time.Now()
	resolvable := false
	r := NewPeerResolver(func(string, uint16) (PeerIdentity, bool) {
		if !resolvable {
			return PeerIdentity{}, false
		}
		return PeerIdentity{Service: "checkout", Namespace: "shop"}, true
	})
	r.now = func() time.Time { return clock }

	if _, ok := r.Resolve("10.244.1.7", 8080); ok {
		t.Fatal("the first resolution drew an edge before any Service claimed the address")
	}

	resolvable = true
	clock = clock.Add(peerNegativeCacheTTL + time.Second)

	if identity, _ := r.Resolve("10.244.1.7", 8080); identity.Service != "checkout" {
		t.Errorf("after the negative entry expired the address resolved to %q, want checkout",
			identity.Service)
	}
}

func TestTheCacheIsBoundedAndDropsExpiredEntriesFirst(t *testing.T) {
	clock := time.Now()
	r := NewPeerResolver(staticPeers(nil))
	r.now = func() time.Time { return clock }
	r.max = 8

	for i := 0; i < 100; i++ {
		r.Resolve(fmt.Sprintf("93.184.%d.%d", i/256, i%256), 8080)
	}
	if got := r.size(); got > 8 {
		t.Fatalf("cache holds %d entries with a max of 8. A workload talking to the internet "+
			"would otherwise accumulate an entry per remote address", got)
	}

	clock = clock.Add(peerCacheTTL + time.Minute)
	if _, ok := r.Resolve("93.184.9.9", 443); !ok {
		t.Fatal("a full cache stopped answering")
	}
	if got := r.size(); got == 0 {
		t.Error("expiring every entry left the cache unable to admit a new one")
	}
}

func TestAFullCacheStillAnswers(t *testing.T) {
	r := NewPeerResolver(staticPeers(map[string]PeerIdentity{
		"10.244.9.9": {Service: "checkout", Namespace: "shop"},
	}))
	r.max = 1
	r.Resolve("10.244.1.1", 8080)

	identity, ok := r.Resolve("10.244.9.9", 8080)
	if !ok || identity.Service != "checkout" {
		t.Errorf("a full cache returned %+v (ok=%v); it must serve answers without caching "+
			"them rather than refusing to resolve", identity, ok)
	}
}

func TestConcurrentResolutionIsSafe(t *testing.T) {
	r := NewPeerResolver(staticPeers(map[string]PeerIdentity{
		"10.244.1.7": {Service: "checkout", Namespace: "shop"},
	}))

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				r.Resolve(fmt.Sprintf("10.244.1.%d", (n+j)%16), 8080)
			}
		}(i)
	}
	wg.Wait()
}

func endpointSlice(namespace, name, service string, addresses ...string) *discoveryv1.EndpointSlice {
	port := int32(8080)
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{discoveryv1.LabelServiceName: service},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: addresses}},
		Ports:     []discoveryv1.EndpointPort{{Port: &port}},
	}
}

func fakeReaderWith(t *testing.T, slices ...*discoveryv1.EndpointSlice) *fake.ClientBuilder {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	builder := fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&discoveryv1.EndpointSlice{}, endpointIPIndex, endpointIndexFunc())
	for _, s := range slices {
		builder = builder.WithObjects(s)
	}
	return builder
}

func TestEndpointSliceLookupNamesTheOwningService(t *testing.T) {
	c := fakeReaderWith(t, endpointSlice("shop", "checkout-abc", "checkout", "10.244.1.7")).Build()

	identity, ok := endpointSliceLookup(c)("10.244.1.7", 8080)
	if !ok {
		t.Fatal("an indexed address did not resolve")
	}
	if identity.Service != "checkout" || identity.Namespace != "shop" {
		t.Errorf("identity = %+v, want checkout/shop", identity)
	}
}

func TestEndpointSliceLookupIgnoresSlicesWithNoService(t *testing.T) {
	orphan := endpointSlice("shop", "orphan", "", "10.244.1.8")
	orphan.Labels = nil
	c := fakeReaderWith(t, orphan).Build()

	if _, ok := endpointSliceLookup(c)("10.244.1.8", 8080); ok {
		t.Error("a slice carrying no service label produced a service name; custom endpoints " +
			"and slices mid-creation belong to no Service")
	}
}

func TestEndpointSliceLookupHandlesNoReaderAndNoMatch(t *testing.T) {
	if _, ok := endpointSliceLookup(nil)("10.244.1.7", 8080); ok {
		t.Error("a nil reader resolved an address")
	}
	c := fakeReaderWith(t).Build()
	if _, ok := endpointSliceLookup(c)("10.244.1.7", 8080); ok {
		t.Error("an unknown address resolved")
	}
}

func TestTrimEndpointSliceKeepsOnlyWhatTheResolverReads(t *testing.T) {
	slice := endpointSlice("shop", "checkout-abc", "checkout", "10.244.1.7")
	slice.Annotations = map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "{}"}
	slice.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "kube-controller-manager"}}
	slice.Labels["unrelated"] = "value"
	hostname := "checkout-0"
	slice.Endpoints[0].Hostname = &hostname

	trimmed, err := trimEndpointSlice(slice)
	if err != nil {
		t.Fatalf("trimEndpointSlice: %v", err)
	}
	got := trimmed.(*discoveryv1.EndpointSlice)

	if got.Annotations != nil || got.ManagedFields != nil {
		t.Error("annotations or managed fields survived. This watch is cluster-wide, so on a " +
			"large cluster it is the agent's biggest cached object set and these dominate it")
	}
	if _, kept := got.Labels["unrelated"]; kept {
		t.Error("an unrelated label survived the trim")
	}
	if got.Labels[discoveryv1.LabelServiceName] != "checkout" {
		t.Error("the service label was trimmed away; it is the one label the resolver reads")
	}
	if got.Endpoints[0].Hostname != nil {
		t.Error("per-endpoint hostname survived")
	}
	if len(got.Endpoints[0].Addresses) != 1 {
		t.Error("addresses were trimmed; they are what the index is built from")
	}
	if len(got.Ports) != 1 {
		t.Error("ports were trimmed. The index keys on address:port, so a slice without its " +
			"ports resolves nothing and every edge silently disappears")
	}
}

func TestTrimEndpointSlicePassesThroughAnythingElse(t *testing.T) {
	other := &metav1.PartialObjectMetadata{}
	got, err := trimEndpointSlice(other)
	if err != nil {
		t.Fatalf("trimEndpointSlice: %v", err)
	}
	if got != any(other) {
		t.Error("a non-EndpointSlice was rewritten")
	}
}

func TestPeerLookupCollapsesANilResolverToANilFunc(t *testing.T) {
	if peerLookup(nil) != nil {
		t.Fatal("a nil resolver produced a non-nil func. The plane leaves the topology " +
			"families unregistered when this is nil, so an interface holding a nil pointer " +
			"would register families that can never be filled")
	}

	r := NewPeerResolver(staticPeers(map[string]PeerIdentity{
		"10.244.1.7": {Service: "checkout", Namespace: "shop"},
	}))
	lookup := peerLookup(r)
	if lookup == nil {
		t.Fatal("a real resolver produced no lookup")
	}
	if identity, ok := lookup("10.244.1.7", 8080); !ok || identity.Service != "checkout" {
		t.Errorf("lookup returned %+v (ok=%v)", identity, ok)
	}
}

var _ = workloadmetrics.PeerIdentity{}

func TestPeerIndexExtractsEveryEndpointAddress(t *testing.T) {
	extract := endpointIndexFunc()

	slice := endpointSlice("shop", "checkout-abc", "checkout", "10.244.1.7", "10.244.1.8")
	slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{Addresses: []string{"10.244.1.9"}})

	got := extract(slice)
	if len(got) != 3 {
		t.Errorf("indexed %v, want one key per address. A Service with several ready endpoints "+
			"must resolve from any of them, or an edge appears only for some replicas", got)
	}
	for _, key := range got {
		if !strings.HasSuffix(key, ":8080") {
			t.Errorf("index key %q does not carry the service port. The port is what keeps the "+
				"map directed: a server replying to a client sees an ephemeral port that "+
				"matches no endpoint, so it draws nothing", key)
		}
	}

	noPorts := endpointSlice("shop", "checkout-abc", "checkout", "10.244.1.7")
	noPorts.Ports = nil
	if out := extract(noPorts); len(out) != 0 {
		t.Errorf("a slice with no ports indexed as %v; there is no endpoint to key on", out)
	}

	bad := int32(70000)
	outOfRange := endpointSlice("shop", "checkout-abc", "checkout", "10.244.1.7")
	outOfRange.Ports = []discoveryv1.EndpointPort{{Port: &bad}}
	if out := extract(outOfRange); len(out) != 0 {
		t.Errorf("an out-of-range port indexed as %v", out)
	}

	if out := extract(&metav1.PartialObjectMetadata{}); out != nil {
		t.Errorf("a non-EndpointSlice indexed as %v, want nil", out)
	}
}

func TestPeerLookupSurfacesAListFailureAsUnresolved(t *testing.T) {
	c := fakeReaderWith(t).Build()
	broken := &failingReader{Client: c}

	if _, ok := endpointSliceLookup(broken)("10.244.1.7", 8080); ok {
		t.Error("a failing cache read reported a resolved peer; the resolver must fall back to " +
			"a placeholder rather than invent a service name")
	}
}

func TestTrimEndpointSliceDropsLabelsWhenThereIsNoServiceName(t *testing.T) {
	slice := endpointSlice("shop", "orphan", "checkout", "10.244.1.7")
	delete(slice.Labels, discoveryv1.LabelServiceName)
	slice.Labels["unrelated"] = "value"

	got, err := trimEndpointSlice(slice)
	if err != nil {
		t.Fatalf("trimEndpointSlice: %v", err)
	}
	if labels := got.(*discoveryv1.EndpointSlice).Labels; labels != nil {
		t.Errorf("labels = %v on a slice with no service name, want nil", labels)
	}
}

func serviceObject(namespace, name, clusterIP string, port int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.ServiceSpec{
			ClusterIP:  clusterIP,
			ClusterIPs: []string{clusterIP},
			Ports:      []corev1.ServicePort{{Port: port}},
		},
	}
}

func clusterReader(t *testing.T, slices []*discoveryv1.EndpointSlice, services []*corev1.Service) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	builder := fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&discoveryv1.EndpointSlice{}, endpointIPIndex, endpointIndexFunc()).
		WithIndex(&corev1.Service{}, serviceIPIndex, serviceIndexFunc())
	for _, s := range slices {
		builder = builder.WithObjects(s)
	}
	for _, s := range services {
		builder = builder.WithObjects(s)
	}
	return builder.Build()
}

func TestAClusterIPResolvesToItsService(t *testing.T) {
	c := clusterReader(t, nil, []*corev1.Service{
		serviceObject("kube-system", "kube-dns", "10.96.0.10", 53),
	})

	identity, ok := clusterPeerLookup(c)("10.96.0.10", 53)
	if !ok {
		t.Fatal("a ClusterIP did not resolve. An unconnected UDP datagram is addressed to the " +
			"ClusterIP and nothing rewrites what the probe reads, so without this most UDP " +
			"flows have no far end to name")
	}
	if identity.Service != "kube-dns" || identity.Namespace != "kube-system" {
		t.Errorf("identity = %+v, want kube-dns/kube-system", identity)
	}
}

func TestABackendAddressWinsOverAClusterIP(t *testing.T) {
	c := clusterReader(t,
		[]*discoveryv1.EndpointSlice{endpointSlice("shop", "payments-abc", "payments", "10.244.1.7")},
		[]*corev1.Service{serviceObject("shop", "decoy", "10.244.1.7", 8080)},
	)

	identity, ok := clusterPeerLookup(c)("10.244.1.7", 8080)
	if !ok {
		t.Fatal("no resolution")
	}
	if identity.Service != "payments" {
		t.Errorf("resolved to %q, want payments. Endpoints are the more specific answer: a "+
			"socket whose destination conntrack rewrote carries a backend address", identity.Service)
	}
}

func TestAHeadlessServiceIsNotIndexedByAddress(t *testing.T) {
	extract := serviceIndexFunc()

	headless := serviceObject("shop", "headless", corev1.ClusterIPNone, 8080)
	headless.Spec.ClusterIPs = []string{corev1.ClusterIPNone}
	if got := extract(headless); len(got) != 0 {
		t.Errorf("a headless Service indexed as %v; it has no address of its own and its "+
			"clients reach the pods directly", got)
	}

	blank := serviceObject("shop", "blank", "", 8080)
	blank.Spec.ClusterIPs = nil
	if got := extract(blank); len(got) != 0 {
		t.Errorf("a Service with no ClusterIP indexed as %v", got)
	}

	if got := extract(&metav1.PartialObjectMetadata{}); got != nil {
		t.Errorf("a non-Service indexed as %v", got)
	}
}

func TestServiceIndexCoversEveryClusterIPAndPort(t *testing.T) {
	svc := serviceObject("shop", "dual", "10.96.0.10", 53)
	svc.Spec.ClusterIPs = []string{"10.96.0.10", "fd00::10"}
	svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Port: 9153})

	got := serviceIndexFunc()(svc)
	if len(got) != 4 {
		t.Errorf("indexed %v, want one key per address-port pair; a dual-stack Service answers "+
			"on both families and a peer may arrive on either", got)
	}
}

func TestTrimServiceKeepsOnlyWhatTheResolverReads(t *testing.T) {
	svc := serviceObject("shop", "payments", "10.96.0.20", 8080)
	svc.Annotations = map[string]string{"a": "b"}
	svc.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "kubectl"}}
	svc.Labels = map[string]string{"app": "payments"}

	trimmed, err := trimService(svc)
	if err != nil {
		t.Fatalf("trimService: %v", err)
	}
	got := trimmed.(*corev1.Service)
	if got.Annotations != nil || got.ManagedFields != nil || got.Labels != nil {
		t.Error("metadata the resolver never reads survived the trim")
	}
	if got.Spec.ClusterIP != "10.96.0.20" || len(got.Spec.Ports) != 1 {
		t.Error("the address or ports were trimmed; they are what the index is built from")
	}
	if got.Name != "payments" || got.Namespace != "shop" {
		t.Error("the identity was trimmed; it is the answer the resolver returns")
	}

	other := &metav1.PartialObjectMetadata{}
	if out, _ := trimService(other); out != any(other) {
		t.Error("a non-Service was rewritten")
	}
}

type recordingIndexer struct {
	registered []string
	failOn     string
}

func (r *recordingIndexer) IndexField(_ context.Context, _ client.Object, field string, extract client.IndexerFunc) error {
	if field == r.failOn {
		return errors.New("index registration refused")
	}
	if extract == nil {
		return errors.New("no extract function")
	}
	r.registered = append(r.registered, field)
	return nil
}

type indexerOnlyManager struct {
	ctrl.Manager
	indexer client.FieldIndexer
}

func (m indexerOnlyManager) GetFieldIndexer() client.FieldIndexer { return m.indexer }

func TestPeerIndexRegistersBothAddressSources(t *testing.T) {
	indexer := &recordingIndexer{}

	if err := RegisterPeerIndex(context.Background(), indexerOnlyManager{indexer: indexer}); err != nil {
		t.Fatalf("RegisterPeerIndex: %v", err)
	}

	want := []string{endpointIPIndex, serviceIPIndex}
	if len(indexer.registered) != len(want) {
		t.Fatalf("registered %v, want %v", indexer.registered, want)
	}
	for i, field := range want {
		if indexer.registered[i] != field {
			t.Errorf("registered[%d] = %q, want %q. Both indexes are load-bearing: endpoints "+
				"name a backend address and the Service index names a ClusterIP, and a peer "+
				"may arrive as either", i, indexer.registered[i], field)
		}
	}
}

func TestPeerIndexRegistrationFailureIsReported(t *testing.T) {
	for _, field := range []string{endpointIPIndex, serviceIPIndex} {
		t.Run(field, func(t *testing.T) {
			indexer := &recordingIndexer{failOn: field}

			err := RegisterPeerIndex(context.Background(), indexerOnlyManager{indexer: indexer})
			if err == nil {
				t.Fatal("a refused index registration was swallowed. Starting the agent with a " +
					"half-registered cache makes every lookup on the missing index fail at " +
					"runtime, which reads as an unresolvable peer rather than a setup fault")
			}
		})
	}
}

func TestServiceIndexFallsBackToTheSingularClusterIP(t *testing.T) {
	svc := serviceObject("shop", "legacy", "10.96.0.5", 80)
	svc.Spec.ClusterIPs = nil

	got := serviceIndexFunc()(svc)
	if len(got) != 1 || got[0] != endpointKey("10.96.0.5", 80) {
		t.Errorf("indexed %v, want the singular ClusterIP. An object written before dual-stack "+
			"carries only spec.clusterIP, and ignoring it would leave those Services unnamed", got)
	}
}

func TestServiceIndexSkipsPortsOutsideTheWireRange(t *testing.T) {
	svc := serviceObject("shop", "odd", "10.96.0.5", 80)
	svc.Spec.Ports = []corev1.ServicePort{{Port: -1}, {Port: 70000}, {Port: 80}}

	got := serviceIndexFunc()(svc)
	if len(got) != 1 || got[0] != endpointKey("10.96.0.5", 80) {
		t.Errorf("indexed %v, want only the port that fits a uint16. A port outside the range "+
			"would wrap when narrowed and index the Service under an address it never answers on", got)
	}
}

func TestServiceLookupReportsUnresolvedRatherThanFailing(t *testing.T) {
	if _, ok := serviceLookup(nil)("10.96.0.10", 53); ok {
		t.Error("a nil reader claimed a resolution")
	}

	if _, ok := serviceLookup(failingReader{})("10.96.0.10", 53); ok {
		t.Error("a failing List claimed a resolution. A cache that has not synced yet must read " +
			"as an unnamed peer, never as a confident wrong name")
	}

	if _, ok := serviceLookup(clusterReader(t, nil, nil))("10.96.0.99", 53); ok {
		t.Error("an address no Service claims resolved anyway")
	}
}

func TestAnUnparseablePeerAddressIsTreatedAsExternal(t *testing.T) {
	resolver := NewPeerResolver(staticPeers(nil))

	identity, ok := resolver.Resolve("not-an-address", 443)
	if !ok || identity.Service != PeerExternal {
		t.Errorf("Resolve(%q) = %+v, %v; want it folded into %q. Only a parseable private "+
			"address is cluster-local, so anything unreadable must fall to the bounded "+
			"external bucket rather than minting an edge of its own",
			"not-an-address", identity, ok, PeerExternal)
	}
}
