package cache

import (
	"container/list"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/metricsexporter"
	"github.com/gma1k/podtrace/internal/validation"
)

type cacheEntry struct {
	pid        uint32
	name       string
	startTicks uint64
	storedAt   time.Time
	expiresAt  time.Time
	element    *list.Element
}

type LRUCache struct {
	cache       map[uint32]*list.Element
	list        *list.List
	maxSize     int
	ttl         time.Duration
	mutex       sync.RWMutex
	stopCleanup chan struct{}
	closeOnce   sync.Once
}

func NewLRUCache(maxSize int, ttl time.Duration) *LRUCache {
	c := &LRUCache{
		cache:       make(map[uint32]*list.Element),
		list:        list.New(),
		maxSize:     maxSize,
		ttl:         ttl,
		stopCleanup: make(chan struct{}),
	}
	go c.cleanupExpired()
	return c
}

// Get returns the name cached for pid, whichever process it was read from.
func (c *LRUCache) Get(pid uint32) (string, bool) {
	return c.lookup(pid, func(*cacheEntry) bool { return true })
}

// GetProcess returns the name cached for the process instance that started
// at startTicks.
func (c *LRUCache) GetProcess(pid uint32, startTicks uint64) (string, bool) {
	return c.lookup(pid, func(e *cacheEntry) bool {
		return e.startTicks != 0 && e.startTicks == startTicks
	})
}

// GetRecent returns the name cached for pid if it was stored within maxAge.
// It serves a process that has already exited, which cannot be identified
// any more, without reaching back to whatever held the pid long ago.
func (c *LRUCache) GetRecent(pid uint32, maxAge time.Duration) (string, bool) {
	now := time.Now()
	return c.lookup(pid, func(e *cacheEntry) bool { return now.Sub(e.storedAt) < maxAge })
}

func (c *LRUCache) lookup(pid uint32, usable func(*cacheEntry) bool) (string, bool) {
	if !validation.ValidatePID(pid) {
		return "", false
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	elem, ok := c.cache[pid]
	if !ok {
		return "", false
	}

	entry := elem.Value.(*cacheEntry)
	if time.Now().After(entry.expiresAt) {
		delete(c.cache, pid)
		c.list.Remove(elem)
		return "", false
	}
	if !usable(entry) {
		return "", false
	}

	c.list.MoveToFront(elem)
	metricsexporter.RecordProcessCacheHit()
	return entry.name, true
}

// Set caches name for pid without naming the process it belongs to.
func (c *LRUCache) Set(pid uint32, name string) {
	c.SetProcess(pid, 0, name)
}

// SetProcess caches name for the process instance (pid, startTicks).
func (c *LRUCache) SetProcess(pid uint32, startTicks uint64, name string) {
	if !validation.ValidatePID(pid) {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	if elem, ok := c.cache[pid]; ok {
		entry := elem.Value.(*cacheEntry)
		entry.name = name
		entry.startTicks = startTicks
		entry.storedAt = now
		entry.expiresAt = now.Add(c.ttl)
		c.list.MoveToFront(elem)
		return
	}

	if len(c.cache) >= c.maxSize {
		c.evict()
	}

	entry := &cacheEntry{
		pid:        pid,
		name:       name,
		startTicks: startTicks,
		storedAt:   now,
		expiresAt:  now.Add(c.ttl),
	}
	elem := c.list.PushFront(entry)
	entry.element = elem
	c.cache[pid] = elem
}

func (c *LRUCache) evict() {
	evictTarget := int(float64(c.maxSize) * config.CacheEvictionThreshold)
	for len(c.cache) >= evictTarget {
		back := c.list.Back()
		if back == nil {
			break
		}
		entry := back.Value.(*cacheEntry)
		delete(c.cache, entry.pid)
		c.list.Remove(back)
	}
}

func (c *LRUCache) cleanupExpired() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mutex.Lock()
			now := time.Now()
			var toRemove []*list.Element
			for _, elem := range c.cache {
				entry := elem.Value.(*cacheEntry)
				if now.After(entry.expiresAt) {
					toRemove = append(toRemove, elem)
				}
			}
			for _, elem := range toRemove {
				entry := elem.Value.(*cacheEntry)
				delete(c.cache, entry.pid)
				c.list.Remove(elem)
			}
			c.mutex.Unlock()
		case <-c.stopCleanup:
			return
		}
	}
}

// Close stops the expiry loop. It is safe to call more than once.
func (c *LRUCache) Close() {
	c.closeOnce.Do(func() { close(c.stopCleanup) })
}
