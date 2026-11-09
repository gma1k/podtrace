package kubernetes

import (
	"sync"
	"time"
)

// maxPodIPCacheEntries bounds the enricher's per-IP lookup cache. A traced
// workload can talk to any number of distinct private addresses, so the
// cache must not grow with them.
const maxPodIPCacheEntries = 4096

// podIPCache is a size-bounded TTL cache keyed by IP. When full it drops
// expired entries first, then the entry closest to expiry.
type podIPCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	max     int
}

func newPodIPCache(max int) *podIPCache {
	return &podIPCache{entries: map[string]*cacheEntry{}, max: max}
}

func (c *podIPCache) Load(ip string) (*cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[ip]
	return e, ok
}

func (c *podIPCache) Delete(ip string) {
	c.mu.Lock()
	delete(c.entries, ip)
	c.mu.Unlock()
}

func (c *podIPCache) Store(ip string, e *cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[ip]; !exists && len(c.entries) >= c.max {
		c.evictLocked(time.Now())
	}
	c.entries[ip] = e
}

func (c *podIPCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *podIPCache) Range(fn func(ip string, e *cacheEntry) bool) {
	c.mu.Lock()
	snapshot := make(map[string]*cacheEntry, len(c.entries))
	for k, v := range c.entries {
		snapshot[k] = v
	}
	c.mu.Unlock()
	for k, v := range snapshot {
		if !fn(k, v) {
			return
		}
	}
}

func (c *podIPCache) evictLocked(now time.Time) {
	for ip, e := range c.entries {
		if !now.Before(e.expiresAt) {
			delete(c.entries, ip)
		}
	}
	if len(c.entries) < c.max {
		return
	}
	var oldestIP string
	var oldest time.Time
	for ip, e := range c.entries {
		if oldestIP == "" || e.expiresAt.Before(oldest) {
			oldestIP, oldest = ip, e.expiresAt
		}
	}
	delete(c.entries, oldestIP)
}
