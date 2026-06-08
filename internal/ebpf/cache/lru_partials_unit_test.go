package cache

import (
	"testing"
	"time"
)

// TestLRUCache_Get_ExpiredInline drives the expired-entry branch *inside*
// Get (lines that delete the stale element and return false). The existing
// TestLRUCache_Get_Expired relies on a real sleep, where the background
// cleanup goroutine may reap the entry first — leaving the inline expiry
// branch in Get uncovered. Here we forge expiresAt into the past while the
// element is still present, so Get itself must take the delete-and-evict path.
func TestLRUCache_Get_ExpiredInline(t *testing.T) {
	c := NewLRUCache(10, time.Hour)
	defer c.Close()

	c.Set(123, "stale-process")

	c.mutex.Lock()
	elem, ok := c.cache[123]
	if !ok {
		c.mutex.Unlock()
		t.Fatalf("expected PID 123 to be present before forcing expiry")
	}
	elem.Value.(*cacheEntry).expiresAt = time.Now().Add(-time.Minute)
	c.mutex.Unlock()

	name, found := c.Get(123)
	if found {
		t.Fatalf("expected Get to report miss for expired entry, got %q", name)
	}
	if name != "" {
		t.Fatalf("expected empty name for expired entry, got %q", name)
	}

	c.mutex.Lock()
	_, stillInMap := c.cache[123]
	listLen := c.list.Len()
	c.mutex.Unlock()
	if stillInMap {
		t.Fatalf("expired entry should have been deleted from the map")
	}
	if listLen != 0 {
		t.Fatalf("expired entry should have been removed from the list, len=%d", listLen)
	}
}
