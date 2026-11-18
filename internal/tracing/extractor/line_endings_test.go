package extractor

import (
	"strings"
	"testing"
)

const lineEndingsTraceParent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func TestParseRawHeadersSplitsBareLineFeeds(t *testing.T) {
	headers := parseRawHeaders("traceparent: " + lineEndingsTraceParent + "\ncontent-type: application/json\nx-request-id: r-1")
	if headers["traceparent"] != lineEndingsTraceParent {
		t.Fatalf("traceparent = %q, want %q", headers["traceparent"], lineEndingsTraceParent)
	}
	if headers["content-type"] != "application/json" || headers["x-request-id"] != "r-1" {
		t.Fatalf("headers = %v", headers)
	}
}

func TestParseRawHeadersAcceptsMixedLineEndings(t *testing.T) {
	headers := parseRawHeaders("a: 1\r\nb: 2\nc: 3\r\n\r\n")
	if len(headers) != 3 || headers["a"] != "1" || headers["b"] != "2" || headers["c"] != "3" {
		t.Fatalf("headers = %v", headers)
	}
}

func TestParseRawHeadersStripsOnlyOneTrailingCarriageReturn(t *testing.T) {
	headers := parseRawHeaders("a: 1\r\r\nb: 2")
	if headers["a"] != "1" || headers["b"] != "2" {
		t.Fatalf("headers = %v", headers)
	}
}

func TestParseRawHeadersSkipsAStatusLineBeforeTheTraceparent(t *testing.T) {
	headers := parseRawHeaders("200\ntraceparent: " + lineEndingsTraceParent + "\ngrpc-status: 0")
	if headers["traceparent"] != lineEndingsTraceParent || headers["grpc-status"] != "0" {
		t.Fatalf("headers = %v", headers)
	}
	if len(headers) != 2 {
		t.Fatalf("headers = %v, the status line is not a header", headers)
	}
}

func TestParseRawHeadersStopsAtTheHeaderCap(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < MaxHeaderCount*3; i++ {
		sb.WriteString("h")
		sb.WriteString(strings.Repeat("x", i))
		sb.WriteString(": v\n")
	}
	if headers := parseRawHeaders(sb.String()); len(headers) != MaxHeaderCount {
		t.Fatalf("len(headers) = %d, want %d", len(headers), MaxHeaderCount)
	}
}

func TestExtractFromRawHeadersFindsTraceparentAmongCapturedHeaders(t *testing.T) {
	cases := map[string]string{
		"request":          "traceparent: " + lineEndingsTraceParent + "\ncontent-type: application/json",
		"held response":    "200\ntraceparent: " + lineEndingsTraceParent,
		"response trailer": "200\ntraceparent: " + lineEndingsTraceParent + "\ngrpc-status: 0",
		"crlf":             "traceparent: " + lineEndingsTraceParent + "\r\nx-request-id: r-1\r\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			tc := NewHTTPExtractor().ExtractFromRawHeaders(raw)
			if tc == nil {
				t.Fatalf("no trace context extracted from %q", raw)
			}
			if tc.TraceID != "0af7651916cd43dd8448eb211c80319c" || tc.ParentSpanID != "b7ad6b7169203331" {
				t.Fatalf("trace context = %+v", tc)
			}
		})
	}
}
