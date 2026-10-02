package report

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/analysis/criticalpath"
)

func TestNoServedRequestMeansNoBreakdown(t *testing.T) {
	if got := GenerateCriticalPathSection(criticalpath.Summary{}, ""); got != "" {
		t.Errorf("section = %q", got)
	}
}

func TestTheBreakdownShowsWhereTheTimeWent(t *testing.T) {
	got := GenerateCriticalPathSection(criticalpath.Summary{
		Requests: 3,
		ByKind:   map[string]int{"HTTP/1": 2, "Go net/http": 1},
		Total:    time.Second,
		ByCategory: map[criticalpath.Category]time.Duration{
			criticalpath.Network:  600 * time.Millisecond,
			criticalpath.Untraced: 400 * time.Millisecond,
		},
		Slowest: []criticalpath.Request{
			{Kind: "HTTP/1", Endpoint: "GET /orders", Namespace: "shop", Pod: "api-0", Latency: 800 * time.Millisecond,
				Shares: []criticalpath.Share{{Category: criticalpath.Network, Duration: 600 * time.Millisecond}, {Category: criticalpath.Untraced, Duration: 200 * time.Millisecond}}},
			{Kind: "Go net/http", Process: "api", Latency: 100 * time.Millisecond,
				Shares: []criticalpath.Share{{Category: criticalpath.Untraced, Duration: 100 * time.Millisecond}}},
		},
		Late:      2,
		Evicted:   1,
		Truncated: 4,
	}, "")
	for _, want := range []string{
		"Request Time Breakdown:",
		"Requests served: 3 (HTTP/1 2, Go net/http 1)",
		"Where their time went: network 60.0%, not in traced I/O 40.0%",
		"800ms",
		"GET /orders  shop/api-0  (HTTP/1)",
		"network 75.0%, not in traced I/O 25.0%",
		"(endpoint not seen)  api  (Go net/http)",
		"Not counted: 2 waits arrived after their request finished; 1 requests were dropped unfinished; 4 requests had more waits than were kept",
		"the shares add up to the request",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("section lacks %q:\n%s", want, got)
		}
	}
}

func TestTheBreakdownOmitsGapsAndSlowestWhenThereAreNone(t *testing.T) {
	got := GenerateCriticalPathSection(criticalpath.Summary{Requests: 1, ByKind: map[string]int{"HTTP/1": 1}}, "")
	for _, absent := range []string{"Slowest requests", "Not counted"} {
		if strings.Contains(got, absent) {
			t.Errorf("section has %q:\n%s", absent, got)
		}
	}
	if !strings.Contains(got, "Where their time went: -") {
		t.Errorf("a request of zero duration was given shares:\n%s", got)
	}
}

func TestTheBreakdownStripsTerminalControlFromAnEndpoint(t *testing.T) {
	got := GenerateCriticalPathSection(criticalpath.Summary{
		Requests: 1, ByKind: map[string]int{"HTTP/1": 1}, Total: time.Millisecond,
		Slowest: []criticalpath.Request{{Kind: "HTTP/1", Endpoint: "GET /\x1b[2Jx", Latency: time.Millisecond}},
	}, "")
	if strings.Contains(got, "\x1b") {
		t.Errorf("an escape sequence reached the report: %q", got)
	}
}

func TestKindsWithEqualCountsAreListedByName(t *testing.T) {
	if got := kindCounts(map[string]int{"HTTP/2": 1, "HTTP/1": 1}); got != "HTTP/1 1, HTTP/2 1" {
		t.Errorf("kinds = %q", got)
	}
	shares := sharesOf(map[criticalpath.Category]time.Duration{criticalpath.Lock: time.Second, criticalpath.Cache: time.Second})
	if shares[0].Category != criticalpath.Cache {
		t.Errorf("equal shares are not ordered by name: %+v", shares)
	}
}

func TestTheBreakdownListsTheEndpointsWithTheMostTime(t *testing.T) {
	var endpoints []criticalpath.EndpointSummary
	for i := 0; i < 7; i++ {
		endpoints = append(endpoints, criticalpath.EndpointSummary{
			Endpoint: fmt.Sprintf("GET /e%d", i), Requests: 2, Total: time.Duration(7-i) * time.Second,
			ByCategory: map[criticalpath.Category]time.Duration{criticalpath.Network: time.Duration(7-i) * time.Second},
		})
	}
	got := GenerateCriticalPathSection(criticalpath.Summary{
		Requests: 14, ByKind: map[string]int{"HTTP/1": 14}, Total: 28 * time.Second, ByEndpoint: endpoints,
	}, "")
	for _, want := range []string{
		"By endpoint, most total time first:",
		"GET /e0  2 requests, mean 3.5s",
		"network 100.0%",
		"GET /e4  2 requests",
		"... 2 more endpoints",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("section lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "GET /e5") {
		t.Errorf("more than %d endpoints were listed:\n%s", endpointsShown, got)
	}
}

func TestSharesBelowATenthOfAPercentAreLeftOut(t *testing.T) {
	got := formatShares([]criticalpath.Share{
		{Category: criticalpath.Network, Duration: 9999},
		{Category: criticalpath.Connect, Duration: 1},
	}, 10000)
	if got != "network 100.0%" {
		t.Errorf("shares = %q", got)
	}
	if got := formatShares([]criticalpath.Share{{Category: criticalpath.Lock, Duration: 1}}, 1_000_000); got != "-" {
		t.Errorf("shares that all round to nothing = %q", got)
	}
}

func TestDurationsKeepTheirSignificantDigits(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		47 * time.Microsecond:                         47 * time.Microsecond,
		302*time.Millisecond + 449*time.Microsecond:   302*time.Millisecond + 400*time.Microsecond,
		10*time.Second + 46*time.Millisecond + 700000: 10*time.Second + 47*time.Millisecond,
	} {
		if got := roundForReading(in); got != want {
			t.Errorf("roundForReading(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestAFilteredRunSaysWhichWaitsWereKept(t *testing.T) {
	s := criticalpath.Summary{Requests: 1, ByKind: map[string]int{"HTTP/1": 1}, Total: time.Second,
		ByCategory: map[criticalpath.Category]time.Duration{criticalpath.Untraced: time.Second}}
	if got := GenerateCriticalPathSection(s, "dns"); !strings.Contains(got, "Only waits in the filtered categories (dns) were kept") {
		t.Errorf("a filtered run does not say its waits were filtered:\n%s", got)
	}
	if got := GenerateCriticalPathSection(s, ""); strings.Contains(got, "filtered categories") {
		t.Errorf("an unfiltered run mentions a filter:\n%s", got)
	}
}
