package kubernetes

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/logger"
	"go.uber.org/zap"
)

const (
	podIPIndex     = "podIP"
	ipPortIndex    = "ipPort"
	ipOnlyIndex    = "ipOnly"
	serviceNameKey = "kubernetes.io/service-name"
)

type InformerCache struct {
	clientset  kubernetes.Interface
	namespaces []string

	mu      sync.RWMutex
	started bool
	stopCh  chan struct{}

	podInfs []cache.SharedIndexInformer
	esInfs  []cache.SharedIndexInformer
}

func NewInformerCache(clientset kubernetes.Interface) *InformerCache {
	return NewScopedInformerCache(clientset, nil)
}

// NewScopedInformerCache builds a cache that watches cluster-wide when the
// identity may, and otherwise only the given namespaces it may list in, so a
// reflector never retries a Forbidden LIST forever.
func NewScopedInformerCache(clientset kubernetes.Interface, namespaces []string) *InformerCache {
	return &InformerCache{clientset: clientset, namespaces: uniqNonEmpty(namespaces)}
}

func (ic *InformerCache) Enabled() bool {
	return config.K8sUseInformers()
}

func (ic *InformerCache) Start(ctx context.Context) {
	if ic == nil || ic.clientset == nil || !ic.Enabled() {
		return
	}

	ic.mu.Lock()
	if ic.started {
		ic.mu.Unlock()
		return
	}
	ic.started = true
	ic.stopCh = make(chan struct{})
	stopCh := ic.stopCh
	ic.mu.Unlock()

	podScopes := ic.listableScopes(ctx, func(ns string) error {
		_, err := ic.clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{Limit: 1})
		return err
	})
	esScopes := ic.listableScopes(ctx, func(ns string) error {
		_, err := ic.clientset.DiscoveryV1().EndpointSlices(ns).List(ctx, metav1.ListOptions{Limit: 1})
		return err
	})

	factories := map[string]informers.SharedInformerFactory{}
	factoryFor := func(ns string) informers.SharedInformerFactory {
		if f, ok := factories[ns]; ok {
			return f
		}
		f := informers.NewSharedInformerFactoryWithOptions(ic.clientset, 0, informers.WithNamespace(ns))
		factories[ns] = f
		return f
	}
	var podInfs, esInfs []cache.SharedIndexInformer
	var syncFns []cache.InformerSynced
	for _, ns := range podScopes {
		inf := factoryFor(ns).Core().V1().Pods().Informer()
		_ = inf.SetTransform(trimPodForCache)
		_ = inf.AddIndexers(cache.Indexers{podIPIndex: indexPodIPs})
		podInfs = append(podInfs, inf)
		syncFns = append(syncFns, inf.HasSynced)
	}
	for _, ns := range esScopes {
		inf := factoryFor(ns).Discovery().V1().EndpointSlices().Informer()
		_ = inf.SetTransform(trimEndpointSliceForCache)
		_ = inf.AddIndexers(cache.Indexers{
			ipOnlyIndex: indexEndpointSliceIPs,
			ipPortIndex: indexEndpointSliceIPPorts,
		})
		esInfs = append(esInfs, inf)
		syncFns = append(syncFns, inf.HasSynced)
	}

	ic.mu.Lock()
	ic.podInfs = podInfs
	ic.esInfs = esInfs
	ic.mu.Unlock()

	for _, f := range factories {
		f.Start(stopCh)
	}
	if len(syncFns) == 0 {
		return
	}

	timeoutSec := 2
	if v := os.Getenv("PODTRACE_K8S_INFORMERS_SYNC_TIMEOUT_SEC"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			timeoutSec = i
		}
	}

	syncCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	if !cache.WaitForCacheSync(syncCtx.Done(), syncFns...) {
		logger.Warn("Kubernetes informer cache did not sync within timeout; enrichment lookups may be incomplete until sync finishes",
			zap.Int("timeout_seconds", timeoutSec))
	}
}

// listableScopes returns where one resource can be watched: cluster-wide
// unless that LIST is Forbidden, then each fallback namespace whose LIST is
// not.
func (ic *InformerCache) listableScopes(ctx context.Context, list func(namespace string) error) []string {
	err := list(metav1.NamespaceAll)
	if err == nil || !apierrors.IsForbidden(err) {
		return []string{metav1.NamespaceAll}
	}
	var scopes []string
	for _, ns := range ic.namespaces {
		if err := list(ns); err == nil || !apierrors.IsForbidden(err) {
			scopes = append(scopes, ns)
		}
	}
	if len(scopes) == 0 {
		logger.Debug("Kubernetes enrichment informer not started: listing is forbidden cluster-wide and in every target namespace",
			zap.Strings("namespaces", ic.namespaces))
	}
	return scopes
}

func indexPodIPs(obj interface{}) ([]string, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok || pod == nil {
		return nil, nil
	}
	return podIPs(pod), nil
}

func indexEndpointSliceIPs(obj interface{}) ([]string, error) {
	es, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok || es == nil {
		return nil, nil
	}
	var keys []string
	for _, ep := range es.Endpoints {
		for _, addr := range ep.Addresses {
			if addr != "" {
				keys = append(keys, addr)
			}
		}
	}
	return keys, nil
}

func indexEndpointSliceIPPorts(obj interface{}) ([]string, error) {
	es, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok || es == nil {
		return nil, nil
	}
	var ports []int32
	for _, p := range es.Ports {
		if p.Port != nil {
			ports = append(ports, *p.Port)
		}
	}
	if len(ports) == 0 {
		return nil, nil
	}
	var keys []string
	for _, ep := range es.Endpoints {
		for _, addr := range ep.Addresses {
			if addr == "" {
				continue
			}
			for _, port := range ports {
				keys = append(keys, fmt.Sprintf("%s:%d", addr, port))
			}
		}
	}
	return keys, nil
}

func (ic *InformerCache) Stop() {
	if ic == nil {
		return
	}
	ic.mu.Lock()
	defer ic.mu.Unlock()
	if !ic.started {
		return
	}
	close(ic.stopCh)
	ic.started = false
}

func (ic *InformerCache) GetPodByIP(ip string) *PodMetadata {
	if ic == nil || ip == "" {
		return nil
	}
	var candidates []*corev1.Pod
	for _, inf := range ic.podInformers() {
		objs, err := inf.GetIndexer().ByIndex(podIPIndex, ip)
		if err != nil {
			continue
		}
		for _, obj := range objs {
			if pod, ok := obj.(*corev1.Pod); ok && pod != nil {
				candidates = append(candidates, pod)
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	return podMetadataFor(pickPodForIP(candidates), ip)
}

// PodsSynced reports whether the pod informers hold every pod this identity
// may list, so a miss in them is authoritative and no API fallback is needed.
func (ic *InformerCache) PodsSynced() bool {
	return ic != nil && allSynced(ic.podInformers())
}

// servicesActive reports whether service lookups are answered by the
// EndpointSlice informers, which never fall back to a cluster-wide LIST.
func (ic *InformerCache) servicesActive() bool {
	if ic == nil || !ic.Enabled() {
		return false
	}
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return !ic.started || len(ic.esInfs) > 0
}

func (ic *InformerCache) podInformers() []cache.SharedIndexInformer {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.podInfs
}

func (ic *InformerCache) endpointSliceInformers() []cache.SharedIndexInformer {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.esInfs
}

func allSynced(infs []cache.SharedIndexInformer) bool {
	if len(infs) == 0 {
		return false
	}
	for _, inf := range infs {
		if !inf.HasSynced() {
			return false
		}
	}
	return true
}

// podIPs lists every address a pod holds: the primary IP and, on a
// dual-stack cluster, the other family.
func podIPs(pod *corev1.Pod) []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(ip string) {
		if ip == "" {
			return
		}
		if _, dup := seen[ip]; dup {
			return
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	add(pod.Status.PodIP)
	for _, p := range pod.Status.PodIPs {
		add(p.IP)
	}
	return out
}

func podHasIP(pod *corev1.Pod, ip string) bool {
	for _, p := range podIPs(pod) {
		if p == ip {
			return true
		}
	}
	return false
}

func podIsTerminal(pod *corev1.Pod) bool {
	return pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed
}

// pickPodForIP chooses which pod an address belongs to when several carry
// it.
func pickPodForIP(candidates []*corev1.Pod) *corev1.Pod {
	var live, hostNetwork, finished []*corev1.Pod
	for _, p := range candidates {
		switch {
		case podIsTerminal(p):
			finished = append(finished, p)
		case p.Spec.HostNetwork:
			hostNetwork = append(hostNetwork, p)
		default:
			live = append(live, p)
		}
	}
	for _, tier := range [][]*corev1.Pod{live, hostNetwork, finished} {
		if len(tier) == 0 {
			continue
		}
		if len(tier) == 1 {
			return tier[0]
		}
		return nil
	}
	return nil
}

func podMetadataFor(pod *corev1.Pod, ip string) *PodMetadata {
	if pod == nil {
		return nil
	}
	labels := make(map[string]string, len(pod.Labels))
	for k, v := range pod.Labels {
		labels[k] = v
	}
	return &PodMetadata{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Labels:    labels,
		IP:        ip,
	}
}

func (ic *InformerCache) GetServiceByEndpoint(ip string, port int) *ServiceInfo {
	if ic == nil || ip == "" {
		return nil
	}
	for _, inf := range ic.endpointSliceInformers() {
		var objs []interface{}
		var err error
		if port > 0 {
			objs, err = inf.GetIndexer().ByIndex(ipPortIndex, fmt.Sprintf("%s:%d", ip, port))
		} else {
			objs, err = inf.GetIndexer().ByIndex(ipOnlyIndex, ip)
		}
		if err != nil || len(objs) == 0 {
			continue
		}
		if es, ok := objs[0].(*discoveryv1.EndpointSlice); ok && es != nil {
			return serviceForEndpointSlice(es, port)
		}
	}
	return nil
}

func serviceForEndpointSlice(es *discoveryv1.EndpointSlice, port int) *ServiceInfo {
	svcName := ""
	if es.Labels != nil {
		svcName = es.Labels[serviceNameKey]
		if svcName == "" {
			if v := es.Labels[discoveryv1.LabelServiceName]; v != "" {
				svcName = v
			}
		}
	}
	if svcName == "" {
		return nil
	}

	svcName = strings.TrimSpace(svcName)
	if svcName == "" {
		return nil
	}
	return &ServiceInfo{Name: svcName, Namespace: es.Namespace, Port: port}
}

// trimPodForCache drops everything the enricher never reads before a Pod is
// stored in the shared informer.
func trimPodForCache(obj interface{}) (interface{}, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}
	pod.ManagedFields = nil
	pod.Annotations = nil
	pod.OwnerReferences = nil
	pod.Finalizers = nil
	pod.Spec = corev1.PodSpec{HostNetwork: pod.Spec.HostNetwork}
	pod.Status = corev1.PodStatus{Phase: pod.Status.Phase, PodIP: pod.Status.PodIP, PodIPs: pod.Status.PodIPs}
	return pod, nil
}

// trimEndpointSliceForCache clears the heavy metadata the resolver never reads.
// Endpoints, Ports and Labels (indexed by ipOnlyIndex/ipPortIndex and read by
// GetServiceByEndpoint) are preserved.
func trimEndpointSliceForCache(obj interface{}) (interface{}, error) {
	es, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return obj, nil
	}
	es.ManagedFields = nil
	es.Annotations = nil
	es.OwnerReferences = nil
	es.Finalizers = nil
	return es, nil
}
