package kubernetes

import (
	"context"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ServiceInfo struct {
	Name      string
	Namespace string
	Port      int
}

type ServiceResolver struct {
	clientset     kubernetes.Interface
	endpointCache *sync.Map
	cacheTTL      time.Duration
	negativeTTL   time.Duration
	informerCache *InformerCache

	fetchMu sync.Mutex
}

// endpointCacheEntry is a positive or negative cache row: a negative row
// (notFound=true, shorter TTL) suppresses repeat cluster-wide lists for
// endpoints that simply are not backed by a Service.
type endpointCacheEntry struct {
	serviceInfo ServiceInfo
	notFound    bool
	expiresAt   time.Time
}

func NewServiceResolver(clientset kubernetes.Interface) *ServiceResolver {
	return NewServiceResolverWithCache(clientset, nil)
}

func NewServiceResolverWithCache(clientset kubernetes.Interface, ic *InformerCache) *ServiceResolver {
	ttl := time.Duration(getIntEnvOrDefault("PODTRACE_K8S_CACHE_TTL", 300)) * time.Second
	negativeTTL := 30 * time.Second
	if negativeTTL > ttl {
		negativeTTL = ttl
	}
	return &ServiceResolver{
		clientset:     clientset,
		endpointCache: &sync.Map{},
		cacheTTL:      ttl,
		negativeTTL:   negativeTTL,
		informerCache: ic,
	}
}

func (sr *ServiceResolver) ResolveService(ctx context.Context, ip string, port int) *ServiceInfo {
	if ip == "" || port == 0 || sr.clientset == nil {
		if sr.informerCache != nil && ip != "" {
			return sr.informerCache.GetServiceByEndpoint(ip, port)
		}
		return nil
	}

	if sr.informerCache != nil {
		if svc := sr.informerCache.GetServiceByEndpoint(ip, port); svc != nil {
			return svc
		}
	}

	cacheKey := fmt.Sprintf("%s:%d", ip, port)
	if info, ok := sr.lookupCache(cacheKey); ok {
		return info
	}

	sr.fetchMu.Lock()
	defer sr.fetchMu.Unlock()
	if info, ok := sr.lookupCache(cacheKey); ok {
		return info
	}

	serviceInfo := sr.fetchServiceByEndpoint(ctx, ip, port)
	if serviceInfo == nil {
		sr.endpointCache.Store(cacheKey, &endpointCacheEntry{
			notFound:  true,
			expiresAt: time.Now().Add(sr.negativeTTL),
		})
	}
	return serviceInfo
}

// lookupCache returns (info, true) on a live positive hit, (nil, true) on
// a live negative hit, and (nil, false) when the resolver must fetch.
func (sr *ServiceResolver) lookupCache(cacheKey string) (*ServiceInfo, bool) {
	cached, ok := sr.endpointCache.Load(cacheKey)
	if !ok {
		return nil, false
	}
	entry := cached.(*endpointCacheEntry)
	if time.Now().Before(entry.expiresAt) {
		if entry.notFound {
			return nil, true
		}
		info := entry.serviceInfo
		return &info, true
	}
	sr.endpointCache.Delete(cacheKey)
	return nil, false
}

// fetchServiceByEndpoint lists Endpoints once and populates the positive
// cache for EVERY endpoint in the response, so one cluster-wide list
// amortizes across all subsequent lookups instead of being repeated per
// cache miss.
func (sr *ServiceResolver) fetchServiceByEndpoint(ctx context.Context, ip string, port int) *ServiceInfo {
	endpointsList, err := sr.clientset.CoreV1().Endpoints(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	var match *ServiceInfo
	expiry := time.Now().Add(sr.cacheTTL)
	for _, endpoint := range endpointsList.Items {
		for _, subset := range endpoint.Subsets {
			for _, addr := range subset.Addresses {
				for _, epPort := range subset.Ports {
					info := ServiceInfo{
						Name:      endpoint.Name,
						Namespace: endpoint.Namespace,
						Port:      int(epPort.Port),
					}
					sr.endpointCache.Store(
						fmt.Sprintf("%s:%d", addr.IP, epPort.Port),
						&endpointCacheEntry{serviceInfo: info, expiresAt: expiry},
					)
					if addr.IP == ip && int(epPort.Port) == port && match == nil {
						m := info
						match = &m
					}
				}
			}
		}
	}

	return match
}
