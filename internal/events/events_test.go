package events

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/clock"
)

func TestEvent_Latency(t *testing.T) {
	e := &Event{LatencyNS: 5000000}
	expected := 5 * time.Millisecond
	if e.Latency() != expected {
		t.Errorf("Expected latency %v, got %v", expected, e.Latency())
	}
}

func TestEvent_IsError(t *testing.T) {
	cases := []struct {
		name string
		ev   Event
		want bool
	}{
		{"http 500 is error", Event{Type: EventHTTPResp, Error: 500}, true},
		{"http 200 not error", Event{Type: EventHTTPResp, Error: 0}, false},
		{"negative errno is error", Event{Type: EventTCPRecv, Error: -11}, true},
		{"grpc non-ok is error", Event{Type: EventHTTPResp, Error: 5}, true},
		{"resource utilization 85 not error", Event{Type: EventResourceLimit, Error: 85}, false},
		{"resource utilization 100 not error", Event{Type: EventResourceLimit, Error: 100}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ev.IsError(); got != tc.want {
				t.Errorf("IsError() = %v, want %v (Error=%d, Type=%v)", got, tc.want, tc.ev.Error, tc.ev.Type)
			}
		})
	}
}

func TestEvent_TimestampTime(t *testing.T) {
	ts := uint64(1_000_000_000) // 1s after boot
	e := &Event{Timestamp: ts}
	result := e.TimestampTime()
	expected := clock.BPFTimestampToWall(ts)
	if !result.Equal(expected) {
		t.Errorf("Expected timestamp %v, got %v", expected, result)
	}
}

func TestEvent_TypeString_ResourceLimit(t *testing.T) {
	event := &Event{Type: EventResourceLimit}
	if event.TypeString() != "RESOURCE" {
		t.Errorf("Expected TypeString() = 'RESOURCE', got %s", event.TypeString())
	}
}

func TestEvent_TypeString(t *testing.T) {
	tests := []struct {
		eventType EventType
		expected  string
	}{
		{EventDNS, "DNS"},
		{EventConnect, "NET"},
		{EventTCPSend, "NET"},
		{EventTCPRecv, "NET"},
		{EventWrite, "FS"},
		{EventRead, "FS"},
		{EventFsync, "FS"},
		{EventSchedSwitch, "CPU"},
		{EventPageFault, "MEM"},
		{EventOOMKill, "MEM"},
		{EventHTTPReq, "HTTP"},
		{EventHTTPResp, "HTTP"},
		{EventLockContention, "LOCK"},
		{EventTCPRetrans, "NET"},
		{EventNetDevError, "NET"},
		{EventDBQuery, "DB"},
		{EventExec, "PROC"},
		{EventFork, "PROC"},
		{EventOpen, "FS"},
		{EventClose, "FS"},
		{EventTLSHandshake, "TLS"},
		{EventTLSError, "TLS"},
		{EventResourceLimit, "RESOURCE"},
		{EventType(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			e := &Event{Type: tt.eventType}
			result := e.TypeString()
			if result != tt.expected {
				t.Errorf("Expected type string '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestEvent_HTTPTransport_H2AndH3(t *testing.T) {
	h2cReq := &Event{Type: EventHTTPReq, TCPState: HTTPTransportH2C}
	h2tlsReq := &Event{Type: EventHTTPReq, TCPState: HTTPTransportH2TLS}
	h3Req := &Event{Type: EventHTTPReq, TCPState: HTTPTransportH3}

	if got := h2cReq.HTTPProtoLabel(); got != "HTTP/2" {
		t.Errorf("h2c HTTPProtoLabel() = %q, want HTTP/2", got)
	}
	if got := h2cReq.HTTPScheme(); got != "http" {
		t.Errorf("h2c HTTPScheme() = %q, want http", got)
	}
	if got := h2tlsReq.HTTPProtoLabel(); got != "HTTP/2" {
		t.Errorf("h2-tls HTTPProtoLabel() = %q, want HTTP/2", got)
	}
	if got := h3Req.HTTPProtoLabel(); got != "HTTP/3" {
		t.Errorf("h3 HTTPProtoLabel() = %q, want HTTP/3", got)
	}
	// QUIC is always encrypted: H3 transport must imply the https scheme.
	if got := h3Req.HTTPScheme(); got != "https" {
		t.Errorf("h3 HTTPScheme() = %q, want https", got)
	}
	if got := h3Req.TypeString(); got != "HTTP/3" {
		t.Errorf("h3 TypeString() = %q, want HTTP/3", got)
	}
}

func TestTCPStateString(t *testing.T) {
	tests := []struct {
		state    uint32
		expected string
	}{
		{1, "ESTABLISHED"},
		{2, "SYN_SENT"},
		{3, "SYN_RECV"},
		{4, "FIN_WAIT1"},
		{5, "FIN_WAIT2"},
		{6, "TIME_WAIT"},
		{7, "CLOSE"},
		{8, "CLOSE_WAIT"},
		{9, "LAST_ACK"},
		{10, "LISTEN"},
		{11, "CLOSING"},
		{12, "NEW_SYN_RECV"},
		{99, "UNKNOWN(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := TCPStateString(tt.state)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal", "normal"},
		{"with%percent", "with%%percent"},
		{"multiple%%percent", "multiple%%%%percent"},
		{"no percent", "no percent"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		expected string
	}{
		{"short string", "short", 10, "short"},
		{"exact length", "exact", 5, "exact"},
		{"truncate with ellipsis", "very long string", 10, "very lo..."},
		{"max 3", "long", 3, "lon"},
		{"max 2", "long", 2, "lo"},
		{"max 1", "long", 1, "l"},
		{"max 0", "long", 0, "long"},
		{"max negative", "long", -1, "long"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.max)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func BenchmarkTypeString(b *testing.B) {
	event := &Event{Type: EventDNS}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = event.TypeString()
	}
}

func TestTypeString_UnlinkRename(t *testing.T) {
	tests := []struct {
		et   EventType
		want string
	}{
		{EventUnlink, "FS"},
		{EventRename, "FS"},
	}
	for _, tt := range tests {
		e := &Event{Type: tt.et}
		if got := e.TypeString(); got != tt.want {
			t.Errorf("TypeString(%d): got %q, want %q", tt.et, got, tt.want)
		}
	}
}

// ─── TypeString for new event types ──────────────────────────────────────────

func TestTypeString_PoolEvents(t *testing.T) {
	cases := []struct {
		et   EventType
		want string
	}{
		{EventPoolAcquire, "POOL"},
		{EventPoolRelease, "POOL"},
		{EventPoolExhausted, "POOL"},
	}
	for _, c := range cases {
		e := &Event{Type: c.et}
		if got := e.TypeString(); got != c.want {
			t.Errorf("TypeString(%d) = %q, want %q", c.et, got, c.want)
		}
	}
}

func TestTypeString_FSEvents(t *testing.T) {
	cases := []struct {
		et   EventType
		want string
	}{
		{EventUnlink, "FS"},
		{EventRename, "FS"},
	}
	for _, c := range cases {
		e := &Event{Type: c.et}
		if got := e.TypeString(); got != c.want {
			t.Errorf("TypeString(%d) = %q, want %q", c.et, got, c.want)
		}
	}
}

func TestTypeString_CacheEvents(t *testing.T) {
	cases := []struct {
		et   EventType
		want string
	}{
		{EventRedisCmd, "CACHE"},
		{EventMemcachedCmd, "CACHE"},
	}
	for _, c := range cases {
		e := &Event{Type: c.et}
		if got := e.TypeString(); got != c.want {
			t.Errorf("TypeString(%d) = %q, want %q", c.et, got, c.want)
		}
	}
}

func TestTypeString_FastCGIGRPCKafka(t *testing.T) {
	cases := []struct {
		et   EventType
		want string
	}{
		{EventFastCGIReq, "FASTCGI"},
		{EventFastCGIResp, "FASTCGI"},
		{EventGRPCMethod, "gRPC"},
		{EventKafkaProduce, "KAFKA"},
		{EventKafkaFetch, "KAFKA"},
	}
	for _, c := range cases {
		e := &Event{Type: c.et}
		if got := e.TypeString(); got != c.want {
			t.Errorf("TypeString(%d) = %q, want %q", c.et, got, c.want)
		}
	}
}

func TestTypeString_NetVariants(t *testing.T) {
	cases := []struct {
		et   EventType
		want string
	}{
		{EventTCPState, "NET"},
		{EventUDPSend, "NET"},
		{EventUDPRecv, "NET"},
	}
	for _, c := range cases {
		e := &Event{Type: c.et}
		if got := e.TypeString(); got != c.want {
			t.Errorf("TypeString(%d) = %q, want %q", c.et, got, c.want)
		}
	}
}

func TestEvent_DNSServerAddr_PrefersV6(t *testing.T) {
	v4Only := &Event{DNSServerIP: 0x0a00600a}
	if got := v4Only.DNSServerAddr(); got != "10.96.0.10" {
		t.Errorf("v4 DNSServerAddr = %q, want 10.96.0.10", got)
	}
	none := &Event{}
	if got := none.DNSServerAddr(); got != "" {
		t.Errorf("empty DNSServerAddr = %q, want \"\"", got)
	}
}
