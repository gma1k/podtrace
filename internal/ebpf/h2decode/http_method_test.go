package h2decode

import (
	"testing"

	"golang.org/x/net/http2/hpack"

	"github.com/gma1k/podtrace/internal/events"
)

func respFields(status string, extra ...hpack.HeaderField) []hpack.HeaderField {
	return append([]hpack.HeaderField{hf(":status", status)}, extra...)
}

func TestRequestCarriesTheDecodedMethod(t *testing.T) {
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			d := New()
			enc := newBlockEncoder()
			block := enc.encode(reqFields(method, "/api/orders")...)

			ev := singleEvent(t, d.Ingest(rec(1, DirEgress, 0, 1, block)))
			if ev.HTTPMethod != method {
				t.Errorf("HTTPMethod = %q, want %q. :method is decoded from HPACK here, so "+
					"leaving the field empty makes every HTTP/2 request report the convention's "+
					"_OTHER placeholder", ev.HTTPMethod, method)
			}
		})
	}
}

func TestResponseInheritsTheRequestMethod(t *testing.T) {
	d := New()
	enc := newBlockEncoder()

	const conn, stream = 3, 1
	reqBlock := enc.encode(reqFields("POST", "/api/orders")...)
	if evs := d.Ingest(rec(conn, DirEgress, 0, stream, reqBlock)); len(evs) != 1 {
		t.Fatalf("request produced %d events", len(evs))
	}

	respEnc := newBlockEncoder()
	respBlock := respEnc.encode(respFields("201")...)
	response := rec(conn, DirIngress, 0, stream, respBlock)
	response.Timestamp += 5_000_000
	ev := singleEvent(t, d.Ingest(response))

	if ev.Type != events.EventHTTPResp {
		t.Fatalf("type = %v, want EventHTTPResp", ev.Type)
	}
	if ev.HTTPMethod != "POST" {
		t.Errorf("HTTPMethod = %q, want POST. The L7 duration metric is recorded off the "+
			"response, so a method that only reaches the request event never becomes a label",
			ev.HTTPMethod)
	}
	if ev.LatencyNS == 0 {
		t.Error("no latency on the paired response, so the metric would not be observed at all")
	}
}

func TestAnUnknownMethodIsNotPassedThrough(t *testing.T) {
	for _, method := range []string{"FROBNICATE", "GET\nX-Injected: 1", "gett"} {
		t.Run(method, func(t *testing.T) {
			d := New()
			enc := newBlockEncoder()
			block := enc.encode(reqFields(method, "/api/orders")...)

			evs := d.Ingest(rec(1, DirEgress, 0, 1, block))
			if len(evs) == 0 {
				return
			}
			if evs[0].HTTPMethod != "" {
				t.Errorf("HTTPMethod = %q for an out-of-set method. :method is an arbitrary "+
					"peer-chosen token, so passing it through would give Prometheus an unbounded "+
					"label dimension", evs[0].HTTPMethod)
			}
		})
	}
}

func TestALateJoinedRequestWithNoMethodReportsNone(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	block := enc.encode(reqFields("GET", "/api/orders")...)

	ev := singleEvent(t, d.Ingest(rec(1, DirEgress, 0, 1, block)))
	if ev.HTTPMethod == "" {
		t.Skip("this connection decoded a method, so the placeholder path is not exercised here")
	}

	other := New()
	partial := enc.encode(hf(":scheme", "https"), hf(":authority", "demo.svc"))
	for _, got := range other.Ingest(rec(2, DirEgress, 0, 1, partial)) {
		if got.HTTPMethod != "" {
			t.Errorf("HTTPMethod = %q on a block carrying no :method; the decoder substitutes "+
				"\"?\" for Target readability and that must not become a label",
				got.HTTPMethod)
		}
	}
}
