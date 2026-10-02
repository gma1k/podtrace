package criticalpath

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

const ms = uint64(time.Millisecond)

func wait(id uint64, typ events.EventType, startMS, endMS uint64) *events.Event {
	return &events.Event{Type: typ, CorrelationID: id, Timestamp: endMS * ms, LatencyNS: (endMS - startMS) * ms}
}

func finished(id uint64, startMS, endMS uint64, kind uint32) *events.Event {
	return &events.Event{Type: events.EventRequestDone, CorrelationID: id, Timestamp: endMS * ms, LatencyNS: (endMS - startMS) * ms, TCPState: kind}
}

func shareOf(r Request, c Category) time.Duration {
	for _, s := range r.Shares {
		if s.Category == c {
			return s.Duration
		}
	}
	return 0
}

func sum(r Request) time.Duration {
	var total time.Duration
	for _, s := range r.Shares {
		total += s.Duration
	}
	return total
}

func only(t *testing.T, c *Collector) Request {
	t.Helper()
	s := c.Summary()
	if len(s.Slowest) != 1 {
		t.Fatalf("slowest = %+v, want one request", s.Slowest)
	}
	return s.Slowest[0]
}

func TestADatabaseCallsSocketWaitCountsOnceAsDatabase(t *testing.T) {
	c := New()
	c.Feed(wait(7, events.EventTCPRecv, 1010, 1060))
	c.Feed(wait(7, events.EventDBQuery, 1000, 1070))
	c.Feed(finished(7, 1000, 1100, 0))

	r := only(t, c)
	if got := shareOf(r, Database); got != 70*time.Millisecond {
		t.Errorf("database = %v, want the whole 70ms query", got)
	}
	if got := shareOf(r, Network); got != 0 {
		t.Errorf("network = %v; the socket read under the query was counted twice", got)
	}
	if got := shareOf(r, Untraced); got != 30*time.Millisecond {
		t.Errorf("untraced = %v, want the 30ms outside the query", got)
	}
	if sum(r) != r.Latency {
		t.Errorf("shares sum to %v, request took %v", sum(r), r.Latency)
	}
}

func TestParallelWaitsAreCountedOnce(t *testing.T) {
	c := New()
	c.Feed(wait(9, events.EventTCPRecv, 0, 80))
	c.Feed(wait(9, events.EventTCPRecv, 10, 90))
	c.Feed(finished(9, 0, 100, 0))

	r := only(t, c)
	if got := shareOf(r, Network); got != 90*time.Millisecond {
		t.Errorf("network = %v, want the 90ms the two calls covered together, not 160ms", got)
	}
	if sum(r) != 100*time.Millisecond {
		t.Errorf("shares sum to %v, want the request's 100ms", sum(r))
	}
}

func TestAWaitIsClippedToItsRequest(t *testing.T) {
	c := New()
	c.Feed(wait(3, events.EventRead, 40, 160))
	c.Feed(finished(3, 100, 150, 0))

	r := only(t, c)
	if got := shareOf(r, Filesystem); got != 50*time.Millisecond {
		t.Errorf("filesystem = %v, want only the 50ms inside the request", got)
	}
}

func TestConcurrentRequestsKeepTheirOwnWaits(t *testing.T) {
	c := New()
	c.Feed(wait(1, events.EventTCPRecv, 0, 400))
	c.Feed(wait(2, events.EventRead, 10, 40))
	c.Feed(finished(2, 0, 50, 0))
	c.Feed(finished(1, 0, 410, 0))

	s := c.Summary()
	if len(s.Slowest) != 2 || s.Slowest[0].Latency != 410*time.Millisecond {
		t.Fatalf("slowest = %+v", s.Slowest)
	}
	if got := shareOf(s.Slowest[0], Filesystem); got != 0 {
		t.Errorf("the slow request was charged the other request's read (%v)", got)
	}
	if got := shareOf(s.Slowest[1], Network); got != 0 {
		t.Errorf("the fast request was charged the other request's wait (%v)", got)
	}
	if s.ByCategory[Network] != 400*time.Millisecond || s.ByCategory[Filesystem] != 30*time.Millisecond {
		t.Errorf("by category = %v", s.ByCategory)
	}
	if s.Total != 460*time.Millisecond || s.Requests != 2 || s.ByKind["HTTP/1"] != 2 {
		t.Errorf("summary = %+v", s)
	}
}

func TestARequestWithNoWaitsIsAllUntraced(t *testing.T) {
	c := New()
	c.Feed(finished(5, 0, 20, goBit|1))
	r := only(t, c)
	if len(r.Shares) != 1 || r.Shares[0].Category != Untraced || r.Kind != "Go net/http" {
		t.Errorf("request = %+v", r)
	}
}

func TestTheEndpointComesFromTheRequestsHTTPEvents(t *testing.T) {
	c := New()
	c.Feed(&events.Event{Type: events.EventHTTPReq, CorrelationID: 4, Target: "GET /orders", HTTPMethod: "GET"})
	c.Feed(&events.Event{Type: events.EventHTTPResp, CorrelationID: 4, Target: "GET /ignored"})
	c.Feed(&events.Event{Type: events.EventHTTPReq, CorrelationID: 6, Target: "/v1/items", HTTPMethod: "POST"})
	c.Feed(&events.Event{Type: events.EventHTTPReq, CorrelationID: 8})
	c.Feed(finished(4, 0, 30, 0))
	c.Feed(finished(6, 0, 20, 1))
	c.Feed(finished(8, 0, 10, 2))

	got := map[time.Duration]string{}
	for _, r := range c.Summary().Slowest {
		got[r.Latency] = r.Endpoint
	}
	if got[30*time.Millisecond] != "GET /orders" {
		t.Errorf("HTTP/1 endpoint = %q; its target already starts with the method", got[30*time.Millisecond])
	}
	if got[20*time.Millisecond] != "POST /v1/items" {
		t.Errorf("HTTP/2 endpoint = %q", got[20*time.Millisecond])
	}
	if got[10*time.Millisecond] != "" {
		t.Errorf("a request with no target got endpoint %q", got[10*time.Millisecond])
	}
}

func TestTheRequestCarriesItsPodOrProcess(t *testing.T) {
	c := New()
	done := finished(1, 0, 10, 0)
	done.K8s = &events.K8sMetadata{Namespace: "shop", PodName: "api-0"}
	done.ProcessName = "api"
	c.Feed(done)
	r := only(t, c)
	if r.Namespace != "shop" || r.Pod != "api-0" || r.Process != "api" {
		t.Errorf("request = %+v", r)
	}
}

func TestAWaitAfterItsRequestFinishedIsCountedAsLate(t *testing.T) {
	c := New()
	c.Feed(finished(1, 0, 10, 0))
	c.Feed(wait(1, events.EventTCPSend, 9, 12))
	if s := c.Summary(); s.Late != 1 || len(c.open) != 0 {
		t.Errorf("late = %d, open = %d", s.Late, len(c.open))
	}
}

func TestEventsThatAreNotWaitsAreIgnored(t *testing.T) {
	c := New()
	for _, e := range []*events.Event{
		nil,
		{Type: events.EventTCPRecv, LatencyNS: ms, Timestamp: 2 * ms},
		{Type: events.EventSchedSwitch, CorrelationID: 1, LatencyNS: ms, Timestamp: 2 * ms},
		{Type: events.EventTCPRecv, CorrelationID: 1, Timestamp: 2 * ms},
		{Type: events.EventTCPRecv, CorrelationID: 1, LatencyNS: 3 * ms, Timestamp: 2 * ms},
	} {
		c.Feed(e)
	}
	if len(c.open) != 0 {
		t.Errorf("%d requests were opened by events that are not waits", len(c.open))
	}
	var nilCollector *Collector
	nilCollector.Feed(wait(1, events.EventTCPRecv, 0, 1))
	if s := nilCollector.Summary(); s.Requests != 0 {
		t.Errorf("a nil collector reported %+v", s)
	}
}

func TestOpenRequestsAreBounded(t *testing.T) {
	c := New()
	for id := uint64(1); id <= maxOpenRequests+5; id++ {
		c.Feed(wait(id, events.EventTCPRecv, 0, 1))
	}
	if len(c.open) != maxOpenRequests {
		t.Errorf("%d open requests, want at most %d", len(c.open), maxOpenRequests)
	}
	if s := c.Summary(); s.Evicted != 5 {
		t.Errorf("evicted = %d, want 5", s.Evicted)
	}
	if _, ok := c.open[1]; ok {
		t.Error("the oldest request was kept and a newer one dropped")
	}
}

func TestEvictionSkipsRequestsThatAlreadyFinished(t *testing.T) {
	c := New()
	c.Feed(wait(1, events.EventTCPRecv, 0, 1))
	c.Feed(finished(1, 0, 2, 0))
	for id := uint64(2); id <= maxOpenRequests+1; id++ {
		c.Feed(wait(id, events.EventTCPRecv, 0, 1))
	}
	c.Feed(wait(maxOpenRequests+2, events.EventTCPRecv, 0, 1))
	if s := c.Summary(); s.Evicted != 1 {
		t.Errorf("evicted = %d; a finished request still counted against the bound", s.Evicted)
	}
}

func TestARequestKeepsAtMostMaxIntervals(t *testing.T) {
	c := New()
	for i := uint64(0); i < maxIntervals+10; i++ {
		c.Feed(wait(1, events.EventTCPRecv, i, i+1))
	}
	c.Feed(finished(1, 0, maxIntervals+20, 0))
	s := c.Summary()
	if s.Truncated != 1 || !s.Slowest[0].Truncated {
		t.Errorf("truncated = %d, request %+v", s.Truncated, s.Slowest[0].Truncated)
	}
	if got := shareOf(s.Slowest[0], Network); got != maxIntervals*time.Millisecond {
		t.Errorf("network = %v, want the %d waits that were kept", got, maxIntervals)
	}
}

func TestOnlyTheSlowestRequestsAreKeptSlowestFirst(t *testing.T) {
	c := New()
	for i := uint64(1); i <= 25; i++ {
		c.Feed(finished(i, 0, (i*7)%25+1, 0))
	}
	s := c.Summary()
	if len(s.Slowest) != slowestKept {
		t.Fatalf("kept %d, want %d", len(s.Slowest), slowestKept)
	}
	for i := 1; i < len(s.Slowest); i++ {
		if s.Slowest[i].Latency > s.Slowest[i-1].Latency {
			t.Fatalf("not slowest first: %v before %v", s.Slowest[i-1].Latency, s.Slowest[i].Latency)
		}
	}
	if s.Slowest[0].Latency != 25*time.Millisecond || s.Slowest[slowestKept-1].Latency != 21*time.Millisecond {
		t.Errorf("kept %v .. %v, want 25ms .. 21ms", s.Slowest[0].Latency, s.Slowest[slowestKept-1].Latency)
	}
	c.Feed(finished(99, 0, 1, 0))
	if got := c.Summary().Slowest[slowestKept-1].Latency; got != 21*time.Millisecond {
		t.Errorf("a fast request displaced a slow one: %v", got)
	}
}

func TestTheSummaryIsACopy(t *testing.T) {
	c := New()
	c.Feed(finished(1, 0, 10, 0))
	s := c.Summary()
	s.ByKind["HTTP/1"] = 99
	s.ByCategory[Network] = time.Hour
	s.Slowest[0].Latency = time.Hour
	again := c.Summary()
	if again.ByKind["HTTP/1"] != 1 || again.ByCategory[Network] != 0 || again.Slowest[0].Latency != 10*time.Millisecond {
		t.Errorf("changing a summary changed the collector: %+v", again)
	}
}

func TestFinishedIDsAreForgottenInOrder(t *testing.T) {
	c := New()
	for id := uint64(1); id <= recentlyFinishedSize+3; id++ {
		c.Feed(finished(id, 0, 1, 0))
	}
	if len(c.finished) != recentlyFinishedSize {
		t.Errorf("remembers %d finished ids, want %d", len(c.finished), recentlyFinishedSize)
	}
	for _, id := range []uint64{1, 2, 3} {
		if _, ok := c.finished[id]; ok {
			t.Errorf("id %d is still remembered after newer ones replaced it", id)
		}
	}
}

func TestEndpointsAreBounded(t *testing.T) {
	c := New()
	for id := uint64(1); id <= maxEndpoints+2; id++ {
		c.Feed(&events.Event{Type: events.EventHTTPReq, CorrelationID: id, Target: "GET /x"})
	}
	c.Feed(&events.Event{Type: events.EventHTTPReq, CorrelationID: maxEndpoints + 2, Target: "GET /again"})
	if len(c.endpoints) != maxEndpoints {
		t.Errorf("%d endpoints kept, want %d", len(c.endpoints), maxEndpoints)
	}
	if c.endpoints[maxEndpoints+2] != "GET /x" {
		t.Errorf("a repeated id replaced its endpoint: %q", c.endpoints[maxEndpoints+2])
	}
}

func TestAnEmptyOrInvertedRequestHasNoShares(t *testing.T) {
	if got := breakdown(10, 10, nil); got != nil {
		t.Errorf("breakdown of an empty request = %v", got)
	}
	c := New()
	c.Feed(&events.Event{Type: events.EventRequestDone, CorrelationID: 1, Timestamp: 5, LatencyNS: 9})
	if r := only(t, c); r.Latency != 0 || len(r.Shares) != 0 {
		t.Errorf("a request whose latency exceeds its timestamp = %+v", r)
	}
}

func TestBreakdownIgnoresAnIntervalOutsideTheRequestOrOfNoCategory(t *testing.T) {
	got := breakdown(100, 200, []interval{
		{start: 0, end: 50, category: Network},
		{start: 120, end: 130, category: "unknown"},
	})
	if len(got) != 1 || got[0].Category != Untraced || got[0].Duration != 100 {
		t.Errorf("breakdown = %+v", got)
	}
}

func TestEveryWaitHasACategory(t *testing.T) {
	for typ, want := range map[events.EventType]Category{
		events.EventDBQuery:        Database,
		events.EventDBAcquire:      Database,
		events.EventRedisCmd:       Cache,
		events.EventMemcachedCmd:   Cache,
		events.EventKafkaProduce:   Messaging,
		events.EventKafkaFetch:     Messaging,
		events.EventDNS:            DNS,
		events.EventTLSHandshake:   TLS,
		events.EventConnect:        Connect,
		events.EventConnectResult:  Connect,
		events.EventTCPSend:        Network,
		events.EventTCPRecv:        Network,
		events.EventUDPSend:        Network,
		events.EventUDPRecv:        Network,
		events.EventRead:           Filesystem,
		events.EventWrite:          Filesystem,
		events.EventFsync:          Filesystem,
		events.EventOpen:           Filesystem,
		events.EventClose:          Filesystem,
		events.EventUnlink:         Filesystem,
		events.EventRename:         Filesystem,
		events.EventLockContention: Lock,
	} {
		if got, ok := CategoryOf(&events.Event{Type: typ}); !ok || got != want {
			t.Errorf("%v = %q,%v want %q", typ, got, ok, want)
		}
	}
	for _, e := range []*events.Event{
		{Type: events.EventUDPSend, PeerDstPort: 53},
		{Type: events.EventUDPRecv, PeerSrcPort: 53},
	} {
		if got, _ := CategoryOf(e); got != DNS {
			t.Errorf("UDP to or from port 53 = %q, want dns", got)
		}
	}
	if _, ok := CategoryOf(&events.Event{Type: events.EventHTTPResp}); ok {
		t.Error("an HTTP response was treated as a wait")
	}
}

func TestEveryKindHasAName(t *testing.T) {
	for kind, want := range map[uint32]string{
		0: "HTTP/1", 1: "HTTP/2", 2: "HTTP/3", 7: "other",
		goBit | 1: "Go net/http", goBit | 2: "Go HTTP/2", goBit | 3: "Go gRPC", goBit | 4: "Go HTTP/3", goBit | 9: "Go",
	} {
		if got := KindName(kind); got != want {
			t.Errorf("KindName(%#x) = %q, want %q", kind, got, want)
		}
	}
}

func TestTheOpenOrderDoesNotGrowWithFinishedRequests(t *testing.T) {
	c := New()
	c.Feed(wait(1_000_000, events.EventTCPRecv, 0, 1))
	for id := uint64(1); id <= 2*maxOpenRequests+2; id++ {
		c.Feed(wait(id, events.EventTCPRecv, 0, 1))
		c.Feed(finished(id, 0, 2, 0))
	}
	if len(c.openOrder) > 2*maxOpenRequests {
		t.Errorf("the open order holds %d ids for %d open requests", len(c.openOrder), len(c.open))
	}
	if len(c.openOrder) == 0 || c.openOrder[0] != 1_000_000 {
		t.Errorf("compaction lost the request still open: %v", c.openOrder[:min(3, len(c.openOrder))])
	}
}

func TestEachEndpointSumsItsRequests(t *testing.T) {
	c := New()
	for id := uint64(1); id <= 3; id++ {
		c.Feed(&events.Event{Type: events.EventHTTPReq, CorrelationID: id, Target: "GET /slow"})
		c.Feed(wait(id, events.EventTCPRecv, 0, 90))
		c.Feed(finished(id, 0, 100, 0))
	}
	c.Feed(&events.Event{Type: events.EventHTTPReq, CorrelationID: 10, Target: "GET /fast"})
	c.Feed(finished(10, 0, 2, 0))
	c.Feed(finished(11, 0, 1, goBit|1))

	byEndpoint := c.Summary().ByEndpoint
	if len(byEndpoint) != 3 || byEndpoint[0].Endpoint != "GET /slow" {
		t.Fatalf("endpoints = %+v, want /slow first", byEndpoint)
	}
	slow := byEndpoint[0]
	if slow.Requests != 3 || slow.Total != 300*time.Millisecond || slow.ByCategory[Network] != 270*time.Millisecond {
		t.Errorf("/slow = %+v", slow)
	}
	if byEndpoint[2].Endpoint != UnknownEndpoint || byEndpoint[2].Requests != 1 {
		t.Errorf("a request with no endpoint = %+v", byEndpoint[2])
	}
}

func TestEndpointsPastTheBoundAreFoldedTogether(t *testing.T) {
	c := New()
	for id := uint64(1); id <= maxEndpointSummaries+3; id++ {
		c.Feed(&events.Event{Type: events.EventHTTPReq, CorrelationID: id, Target: fmt.Sprintf("GET /item/%d", id)})
		c.Feed(finished(id, 0, 1, 0))
	}
	byEndpoint := c.Summary().ByEndpoint
	if len(byEndpoint) != maxEndpointSummaries {
		t.Fatalf("%d endpoint summaries, want %d", len(byEndpoint), maxEndpointSummaries)
	}
	var other *EndpointSummary
	for i := range byEndpoint {
		if byEndpoint[i].Endpoint == OtherEndpoints {
			other = &byEndpoint[i]
		}
	}
	if other == nil || other.Requests != 4 {
		t.Errorf("other endpoints = %+v, want the 4 requests past the bound", other)
	}
}

func TestEndpointsWithEqualTimeAreOrderedByName(t *testing.T) {
	c := New()
	for id, target := range map[uint64]string{1: "GET /b", 2: "GET /a"} {
		c.Feed(&events.Event{Type: events.EventHTTPReq, CorrelationID: id, Target: target})
		c.Feed(finished(id, 0, 5, 0))
	}
	byEndpoint := c.Summary().ByEndpoint
	if byEndpoint[0].Endpoint != "GET /a" {
		t.Errorf("order = %v, %v", byEndpoint[0].Endpoint, byEndpoint[1].Endpoint)
	}
	byEndpoint[0].ByCategory[Network] = time.Hour
	if c.Summary().ByEndpoint[0].ByCategory[Network] != 0 {
		t.Error("changing an endpoint summary changed the collector")
	}
}

func TestANanosecondCountBeyondADurationIsClampedNotWrapped(t *testing.T) {
	if got := nanoseconds(math.MaxUint64); got != time.Duration(math.MaxInt64) {
		t.Errorf("nanoseconds(MaxUint64) = %v, want the largest Duration", got)
	}
	if got := nanoseconds(1500); got != 1500*time.Nanosecond {
		t.Errorf("nanoseconds(1500) = %v", got)
	}
}
