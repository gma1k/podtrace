package h3decode

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestBothH3EventsCarryTheDecodedMethod(t *testing.T) {
	for _, method := range []string{"GET", "POST", "DELETE", "OPTIONS", "CONNECT"} {
		t.Run(method, func(t *testing.T) {
			txn := &Txn{
				Timestamp: 1_000_000,
				LatencyNS: 4_000_000,
				Status:    200,
				Method:    method,
				Path:      "/api/orders",
			}

			evs := txn.Events()
			if len(evs) != 2 {
				t.Fatalf("got %d events, want a request and a response", len(evs))
			}
			for _, ev := range evs {
				if ev.HTTPMethod != method {
					t.Errorf("%v event HTTPMethod = %q, want %q. QPACK decodes :method here, "+
						"so leaving it empty makes every HTTP/3 request report the convention's "+
						"_OTHER placeholder", ev.Type, ev.HTTPMethod, method)
				}
			}
		})
	}
}

func TestH3MethodIsNotInventedWhenQPACKCarriedNone(t *testing.T) {
	txn := &Txn{Timestamp: 1_000_000, LatencyNS: 1, Status: 200, Path: "/x"}

	for _, ev := range txn.Events() {
		if ev.HTTPMethod != "" {
			t.Errorf("HTTPMethod = %q with no :method decoded. Target falls back to GET for "+
				"readability, but the metric label must not assert a method never observed",
				ev.HTTPMethod)
		}
		if ev.Target != "GET /x" {
			t.Errorf("Target = %q, want the readable GET fallback preserved", ev.Target)
		}
	}
}

func TestH3OutOfSetMethodIsNotPassedThrough(t *testing.T) {
	txn := &Txn{Timestamp: 1, LatencyNS: 1, Status: 200, Method: "FROBNICATE", Path: "/x"}

	for _, ev := range txn.Events() {
		if ev.HTTPMethod != "" {
			t.Errorf("HTTPMethod = %q for an out-of-set method", ev.HTTPMethod)
		}
		if ev.Target != "FROBNICATE /x" {
			t.Errorf("Target = %q; the diagnostic view should still show what was observed",
				ev.Target)
		}
	}
}

func TestResponseOnlyH3TransactionStillCarriesTheMethod(t *testing.T) {
	txn := &Txn{
		Timestamp: 1, LatencyNS: 1, Status: 503,
		Method: "PUT", Path: "/x", Flags: FlagResponseOnly,
	}

	evs := txn.Events()
	if len(evs) != 1 || evs[0].Type != events.EventHTTPResp {
		t.Fatalf("got %d events, want one response", len(evs))
	}
	if evs[0].HTTPMethod != "PUT" {
		t.Errorf("HTTPMethod = %q, want PUT", evs[0].HTTPMethod)
	}
}
