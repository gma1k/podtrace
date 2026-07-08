package tracing

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

// correlationKey identifies one L7 request across its request and response
// events.
func correlationKey(e *events.Event) string {
	return strconv.FormatUint(e.CorrelationID, 10)
}

// deriveSpanID produces a stable 8-byte span id from a correlation key.
func deriveSpanID(key string) string {
	sum := sha256.Sum256([]byte("span\x00" + key))
	return hex.EncodeToString(sum[:8])
}

// deriveTraceID produces a stable 16-byte trace id from a correlation key,
// used only when synthesizing a trace for context-less traffic.
func deriveTraceID(key string) string {
	sum := sha256.Sum256([]byte("trace\x00" + key))
	return hex.EncodeToString(sum[:16])
}

// correlationEntry is the inbound trace context of a request, held until its
// response event arrives so the response (which carries no headers) can join
// the same span.
type correlationEntry struct {
	traceID      string
	parentSpanID string
	spanID       string
	flags        uint8
	state        string
	storedNS     int64
}

// correlationCache carries a request's inbound trace context to its response
// event.
type correlationCache struct {
	mu         sync.Mutex
	m          map[string]correlationEntry
	maxEntries int
}

func newCorrelationCache(maxEntries int) *correlationCache {
	return &correlationCache{m: make(map[string]correlationEntry), maxEntries: maxEntries}
}

func (c *correlationCache) store(key string, e correlationEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.maxEntries {
		c.m = make(map[string]correlationEntry, c.maxEntries)
	}
	e.storedNS = time.Now().UnixNano()
	c.m[key] = e
}

func (c *correlationCache) loadDelete(key string) (correlationEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if ok {
		delete(c.m, key)
	}
	return e, ok
}

// sweep drops entries older than maxAge (requests that never got a response).
func (c *correlationCache) sweep(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge).UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.m {
		if e.storedNS < cutoff {
			delete(c.m, k)
		}
	}
}

// isCorrelatableL7 reports whether an event is one half of an L7 request/
// response pair that carries a correlation id. HTTP/1.x, HTTP/2, HTTP/3 and
// gRPC all surface as EventHTTPReq/EventHTTPResp.
func isCorrelatableL7(e *events.Event) bool {
	return e.CorrelationID != 0 &&
		(e.Type == events.EventHTTPReq || e.Type == events.EventHTTPResp)
}