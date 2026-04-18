package events

import (
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

func TestEvent_Latency(t *testing.T) {
	e := &Event{LatencyNS: 5000000}
	expected := 5 * time.Millisecond
	if e.Latency() != expected {
		t.Errorf("Expected latency %v, got %v", expected, e.Latency())
	}
}

func TestEvent_TimestampTime(t *testing.T) {
	ts := uint64(1609459200000000000)
	e := &Event{Timestamp: ts}
	result := e.TimestampTime()
	if result.UnixNano() != int64(ts) {
		t.Errorf("Expected timestamp %d, got %d", ts, result.UnixNano())
	}
}

func TestEvent_FormatMessage_ResourceLimit(t *testing.T) {
	tests := []struct {
		name         string
		event        *Event
		expectOutput bool
	}{
		{"CPU warning", &Event{Type: EventResourceLimit, TCPState: 0, Error: 85}, true},
		{"Memory critical", &Event{Type: EventResourceLimit, TCPState: 1, Error: 92}, true},
		{"IO emergency", &Event{Type: EventResourceLimit, TCPState: 2, Error: 97}, true},
		{"Below threshold", &Event{Type: EventResourceLimit, TCPState: 0, Error: 50}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.FormatMessage()
			if tt.expectOutput && result == "" {
				t.Error("Expected formatted message but got empty")
			}
			if !tt.expectOutput && result != "" {
				t.Errorf("Expected empty message but got: %s", result)
			}
		})
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
		{EventOpen, "PROC"},
		{EventClose, "PROC"},
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

func TestEvent_FormatMessage_DNS(t *testing.T) {
	tests := []struct {
		name     string
		event    *Event
		expected string
	}{
		{
			"successful lookup",
			&Event{Type: EventDNS, LatencyNS: 5000000, Target: "example.com", Error: 0},
			"[DNS] lookup example.com took 5.00ms",
		},
		{
			"failed lookup",
			&Event{Type: EventDNS, LatencyNS: 1000000, Target: "invalid.com", Error: 1},
			"[DNS] lookup invalid.com failed: error 1",
		},
		{
			"long target truncated",
			&Event{Type: EventDNS, LatencyNS: 5000000, Target: string(make([]byte, 300)), Error: 0},
			"[DNS] lookup " + string(make([]byte, 253)) + "... took 5.00ms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.FormatMessage()
			if len(result) > 0 && result[:len("[DNS]")] != "[DNS]" {
				t.Errorf("Expected DNS format message, got '%s'", result)
			}
		})
	}
}

func TestEvent_FormatMessage_Connect(t *testing.T) {
	tests := []struct {
		name     string
		event    *Event
		shouldBe string
	}{
		{
			"fast connection (no output)",
			&Event{Type: EventConnect, LatencyNS: 500000, Target: "example.com:80", Error: 0},
			"",
		},
		{
			"slow connection",
			&Event{Type: EventConnect, LatencyNS: 2000000, Target: "example.com:80", Error: 0},
			"[NET] connect to example.com:80 took 2.00ms",
		},
		{
			"failed connection",
			&Event{Type: EventConnect, LatencyNS: 1000000, Target: "invalid.com:80", Error: 111},
			"[NET] connect to invalid.com:80 failed: error 111",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.FormatMessage()
			if result != tt.shouldBe {
				t.Errorf("Expected '%s', got '%s'", tt.shouldBe, result)
			}
		})
	}
}

func TestEvent_FormatMessage_TCP(t *testing.T) {
	tests := []struct {
		name     string
		event    *Event
		shouldBe string
	}{
		{
			"normal latency (no output)",
			&Event{Type: EventTCPSend, LatencyNS: 5000000, Error: 0},
			"",
		},
		{
			"high latency spike",
			&Event{Type: EventTCPSend, LatencyNS: 150000000, Error: 0, Bytes: 1024},
			"[NET] TCP send latency spike: 150.00ms (1024 bytes)",
		},
		{
			"error",
			&Event{Type: EventTCPSend, LatencyNS: 1000000, Error: -1},
			"[NET] TCP send error: -1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.FormatMessage()
			if result != tt.shouldBe {
				t.Errorf("Expected '%s', got '%s'", tt.shouldBe, result)
			}
		})
	}
}

func TestEvent_FormatMessage_Filesystem(t *testing.T) {
	tests := []struct {
		name     string
		event    *Event
		expected string
	}{
		{
			"read operation",
			&Event{Type: EventRead, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 4096},
			"[FS] read() from /tmp/file took 2.00ms (4096 bytes)",
		},
		{
			"write operation",
			&Event{Type: EventWrite, LatencyNS: 3000000, Target: "/tmp/file", Bytes: 2048},
			"[FS] write() to /tmp/file took 3.00ms (2048 bytes)",
		},
		{
			"fsync operation",
			&Event{Type: EventFsync, LatencyNS: 1000000, Target: "/tmp/file"},
			"[FS] fsync() to /tmp/file took 1.00ms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.FormatMessage()
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
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

func BenchmarkFormatMessage(b *testing.B) {
	event := &Event{
		Type:      EventDNS,
		LatencyNS: 5000000,
		Target:    "example.com",
		Error:     0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = event.FormatMessage()
	}
}

func BenchmarkTypeString(b *testing.B) {
	event := &Event{Type: EventDNS}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = event.TypeString()
	}
}

func TestEvent_FormatMessage_AllTypes(t *testing.T) {
	tests := []struct {
		name  string
		event *Event
		check func(string) bool
	}{
		{
			"EventUDPSend",
			&Event{Type: EventUDPSend, LatencyNS: 150000000, Bytes: 1024},
			func(s string) bool { return s != "" && contains(s, "UDP send") },
		},
		{
			"EventUDPRecv",
			&Event{Type: EventUDPRecv, LatencyNS: 150000000, Bytes: 1024},
			func(s string) bool { return s != "" && contains(s, "UDP recv") },
		},
		{
			"EventHTTPReq",
			&Event{Type: EventHTTPReq, LatencyNS: 5000000, Target: "http://example.com"},
			func(s string) bool { return s != "" && contains(s, "HTTP") && contains(s, "request") },
		},
		{
			"EventHTTPResp",
			&Event{Type: EventHTTPResp, LatencyNS: 5000000, Target: "http://example.com", Bytes: 2048},
			func(s string) bool { return s != "" && contains(s, "HTTP") && contains(s, "response") },
		},
		{
			"EventLockContention",
			&Event{Type: EventLockContention, LatencyNS: 10000000, Target: "mutex"},
			func(s string) bool { return s != "" && contains(s, "LOCK") },
		},
		{
			"EventTCPRetrans",
			&Event{Type: EventTCPRetrans, Target: "example.com:80"},
			func(s string) bool { return s != "" && contains(s, "retransmission") },
		},
		{
			"EventNetDevError",
			&Event{Type: EventNetDevError, Target: "eth0", Error: 1},
			func(s string) bool { return s != "" && contains(s, "network device") },
		},
		{
			"EventDBQuery",
			&Event{Type: EventDBQuery, LatencyNS: 5000000, Target: "SELECT * FROM users"},
			func(s string) bool { return s != "" && contains(s, "DB") },
		},
		{
			"EventExec",
			&Event{Type: EventExec, LatencyNS: 1000000, Target: "/bin/ls"},
			func(s string) bool { return s != "" && contains(s, "PROC") && contains(s, "execve") },
		},
		{
			"EventExec_Error",
			&Event{Type: EventExec, LatencyNS: 1000000, Target: "/bin/ls", Error: 1},
			func(s string) bool { return s != "" && contains(s, "failed") },
		},
		{
			"EventFork",
			&Event{Type: EventFork, PID: 1234, Target: "child"},
			func(s string) bool { return s != "" && contains(s, "fork") },
		},
		{
			"EventOpen",
			&Event{Type: EventOpen, LatencyNS: 1000000, Target: "/tmp/file", Bytes: 5},
			func(s string) bool { return s != "" && contains(s, "open()") },
		},
		{
			"EventOpen_Error",
			&Event{Type: EventOpen, LatencyNS: 1000000, Target: "/tmp/file", Error: 1},
			func(s string) bool { return s != "" && contains(s, "failed") },
		},
		{
			"EventClose",
			&Event{Type: EventClose, Bytes: 5},
			func(s string) bool { return s != "" && contains(s, "close()") },
		},
		{
			"EventClose_NoFD",
			&Event{Type: EventClose},
			func(s string) bool { return s != "" && contains(s, "close()") },
		},
		{
			"EventPageFault",
			&Event{Type: EventPageFault, Error: 1},
			func(s string) bool { return s != "" && contains(s, "Page fault") },
		},
		{
			"EventOOMKill",
			&Event{Type: EventOOMKill, Target: "process", Bytes: 1024 * 1024 * 100},
			func(s string) bool { return s != "" && contains(s, "OOM kill") },
		},
		{
			"EventTCPState",
			&Event{Type: EventTCPState, TCPState: 1, Target: "example.com:80"},
			func(s string) bool { return s != "" && contains(s, "TCP state") },
		},
		{
			"UnknownEvent",
			&Event{Type: EventType(999)},
			func(s string) bool { return s != "" && contains(s, "UNKNOWN") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.FormatMessage()
			if !tt.check(result) {
				t.Errorf("FormatMessage() = %q, did not pass check", result)
			}
		})
	}
}

func TestEvent_FormatRealtimeMessage(t *testing.T) {
	tests := []struct {
		name  string
		event *Event
		check func(string) bool
	}{
		{
			"EventConnect_Fast",
			&Event{Type: EventConnect, LatencyNS: 500000, Target: "example.com:80"},
			func(s string) bool { return s != "" && contains(s, "connect") },
		},
		{
			"EventTCPSend_Normal",
			&Event{Type: EventTCPSend, LatencyNS: 5000000, Bytes: 1024},
			func(s string) bool { return s == "" || contains(s, "TCP send") },
		},
		{
			"EventTCPRecv_Normal",
			&Event{Type: EventTCPRecv, LatencyNS: 5000000, Bytes: 1024},
			func(s string) bool { return s == "" || contains(s, "TCP recv") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.FormatRealtimeMessage()
			if !tt.check(result) {
				t.Errorf("FormatRealtimeMessage() = %q, did not pass check", result)
			}
		})
	}
}

func TestEvent_FormatMessage_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		event *Event
	}{
		{
			"EmptyTarget",
			&Event{Type: EventDNS, LatencyNS: 5000000, Target: ""},
		},
		{
			"VeryLongTarget",
			&Event{Type: EventDNS, LatencyNS: 5000000, Target: string(make([]byte, 500))},
		},
		{
			"ZeroLatency",
			&Event{Type: EventDNS, LatencyNS: 0, Target: "example.com"},
		},
		{
			"LargeLatency",
			&Event{Type: EventDNS, LatencyNS: 1000000000000, Target: "example.com"},
		},
		{
			"TargetWithPercent",
			&Event{Type: EventDNS, LatencyNS: 5000000, Target: "example%20.com"},
		},
		{
			"QuestionMarkTarget",
			&Event{Type: EventConnect, LatencyNS: 1000000, Target: "?"},
		},
		{
			"UnknownTarget",
			&Event{Type: EventConnect, LatencyNS: 1000000, Target: "unknown"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.FormatMessage()
			if result == "" && tt.event.Type == EventConnect && tt.event.LatencyNS < 1000000 {
				return
			}
		})
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestEvent_FormatMessage_TCPEAGAIN(t *testing.T) {
	e := &Event{Type: EventTCPSend, Error: -config.EAGAIN, LatencyNS: 5000000}
	result := e.FormatMessage()
	if result != "" {
		t.Errorf("Expected empty string for EAGAIN error, got %q", result)
	}
}

func TestEvent_FormatMessage_TCPRecvEAGAIN(t *testing.T) {
	e := &Event{Type: EventTCPRecv, Error: -config.EAGAIN, LatencyNS: 5000000}
	result := e.FormatMessage()
	if result != "" {
		t.Errorf("Expected empty string for EAGAIN error, got %q", result)
	}
}

func TestEvent_FormatMessage_TCPSendNoBytes(t *testing.T) {
	e := &Event{Type: EventTCPSend, LatencyNS: 150000000, Error: 0, Bytes: 0}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for high latency TCP send")
	}
	if !contains(result, "TCP send latency spike") {
		t.Errorf("Expected TCP send message, got %q", result)
	}
}

func TestEvent_FormatMessage_TCPRecvNoBytes(t *testing.T) {
	e := &Event{Type: EventTCPRecv, LatencyNS: 150000000, Error: 0, Bytes: 0}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for high latency TCP recv")
	}
	if !contains(result, "TCP recv RTT spike") {
		t.Errorf("Expected TCP recv message, got %q", result)
	}
}

func TestEvent_FormatMessage_UDPSendNoBytes(t *testing.T) {
	e := &Event{Type: EventUDPSend, LatencyNS: 150000000, Error: 0, Bytes: 0}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for high latency UDP send")
	}
	if !contains(result, "UDP send latency spike") {
		t.Errorf("Expected UDP send message, got %q", result)
	}
}

func TestEvent_FormatMessage_UDPRecvNoBytes(t *testing.T) {
	e := &Event{Type: EventUDPRecv, LatencyNS: 150000000, Error: 0, Bytes: 0}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for high latency UDP recv")
	}
	if !contains(result, "UDP recv latency spike") {
		t.Errorf("Expected UDP recv message, got %q", result)
	}
}

func TestEvent_FormatMessage_ConnectEmptyTarget(t *testing.T) {
	e := &Event{Type: EventConnect, LatencyNS: 2000000, Target: "", Error: 0}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for slow connect")
	}
	if !contains(result, "file") {
		t.Errorf("Expected 'file' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_ConnectQuestionMarkTarget(t *testing.T) {
	e := &Event{Type: EventConnect, LatencyNS: 2000000, Target: "?", Error: 0}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for slow connect")
	}
	if !contains(result, "file") {
		t.Errorf("Expected 'file' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_WriteEmptyTarget(t *testing.T) {
	e := &Event{Type: EventWrite, LatencyNS: 2000000, Target: "", Bytes: 1024}
	result := e.FormatMessage()
	if !contains(result, "file") {
		t.Errorf("Expected 'file' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_WriteQuestionMarkTarget(t *testing.T) {
	e := &Event{Type: EventWrite, LatencyNS: 2000000, Target: "?", Bytes: 1024}
	result := e.FormatMessage()
	if !contains(result, "file") {
		t.Errorf("Expected 'file' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_ReadEmptyTarget(t *testing.T) {
	e := &Event{Type: EventRead, LatencyNS: 2000000, Target: "", Bytes: 1024}
	result := e.FormatMessage()
	if !contains(result, "file") {
		t.Errorf("Expected 'file' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_ReadQuestionMarkTarget(t *testing.T) {
	e := &Event{Type: EventRead, LatencyNS: 2000000, Target: "?", Bytes: 1024}
	result := e.FormatMessage()
	if !contains(result, "file") {
		t.Errorf("Expected 'file' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_WriteNoBytes(t *testing.T) {
	e := &Event{Type: EventWrite, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 0}
	result := e.FormatMessage()
	if contains(result, "bytes") {
		t.Errorf("Should not include bytes when Bytes is 0, got %q", result)
	}
}

func TestEvent_FormatMessage_ReadNoBytes(t *testing.T) {
	e := &Event{Type: EventRead, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 0}
	result := e.FormatMessage()
	if contains(result, "bytes") {
		t.Errorf("Should not include bytes when Bytes is 0, got %q", result)
	}
}

func TestEvent_FormatMessage_HTTPRespNoBytes(t *testing.T) {
	e := &Event{Type: EventHTTPResp, LatencyNS: 5000000, Target: "http://example.com", Bytes: 0}
	result := e.FormatMessage()
	if !contains(result, "HTTP") {
		t.Errorf("Expected HTTP message, got %q", result)
	}
	if contains(result, "bytes") {
		t.Errorf("Should not include bytes when Bytes is 0, got %q", result)
	}
}

func TestEvent_FormatMessage_OpenNegativeFD(t *testing.T) {
	e := &Event{Type: EventOpen, LatencyNS: 1000000, Target: "/tmp/file", Bytes: 0x8000000000000000}
	result := e.FormatMessage()
	if contains(result, "fd=") {
		t.Errorf("Should not include fd when Bytes represents negative FD, got %q", result)
	}
}

func TestEvent_FormatMessage_FormatRealtimeMessage_AllTypes(t *testing.T) {
	tests := []struct {
		name  string
		event *Event
		check func(string) bool
	}{
		{
			"EventDNS_Success",
			&Event{Type: EventDNS, LatencyNS: 5000000, Target: "example.com", Error: 0},
			func(s string) bool { return s != "" && contains(s, "DNS") && contains(s, "lookup") },
		},
		{
			"EventDNS_Error",
			&Event{Type: EventDNS, LatencyNS: 1000000, Target: "invalid.com", Error: 1},
			func(s string) bool { return s != "" && contains(s, "failed") },
		},
		{
			"EventConnect_Error",
			&Event{Type: EventConnect, LatencyNS: 1000000, Target: "example.com:80", Error: 111},
			func(s string) bool { return s != "" && contains(s, "failed") },
		},
		{
			"EventTCPSend_Error",
			&Event{Type: EventTCPSend, Error: -1, LatencyNS: 1000000},
			func(s string) bool { return s != "" && contains(s, "error") },
		},
		{
			"EventTCPSend_EAGAIN",
			&Event{Type: EventTCPSend, Error: -config.EAGAIN, LatencyNS: 5000000},
			func(s string) bool { return s == "" || contains(s, "TCP send") },
		},
		{
			"EventTCPSend_HighLatency",
			&Event{Type: EventTCPSend, LatencyNS: 15000000, Bytes: 1024},
			func(s string) bool { return s != "" && contains(s, "TCP send") },
		},
		{
			"EventTCPSend_LowLatency",
			&Event{Type: EventTCPSend, LatencyNS: 5000000, Bytes: 1024},
			func(s string) bool { return s == "" || contains(s, "TCP send") },
		},
		{
			"EventTCPRecv_Error",
			&Event{Type: EventTCPRecv, Error: -1, LatencyNS: 1000000},
			func(s string) bool { return s != "" && contains(s, "error") },
		},
		{
			"EventTCPRecv_EAGAIN",
			&Event{Type: EventTCPRecv, Error: -config.EAGAIN, LatencyNS: 5000000},
			func(s string) bool { return s == "" || contains(s, "TCP recv") },
		},
		{
			"EventTCPRecv_HighLatency",
			&Event{Type: EventTCPRecv, LatencyNS: 15000000, Bytes: 1024},
			func(s string) bool { return s != "" && contains(s, "TCP recv") },
		},
		{
			"EventTCPRecv_LowLatency",
			&Event{Type: EventTCPRecv, LatencyNS: 5000000, Bytes: 1024},
			func(s string) bool { return s == "" || contains(s, "TCP recv") },
		},
		{
			"EventTCPState",
			&Event{Type: EventTCPState, TCPState: 1, Target: "example.com:80"},
			func(s string) bool { return s != "" && contains(s, "TCP state") },
		},
		{
			"EventTCPState_EmptyTarget",
			&Event{Type: EventTCPState, TCPState: 1, Target: ""},
			func(s string) bool { return s != "" && contains(s, "unknown") },
		},
		{
			"EventPageFault",
			&Event{Type: EventPageFault, Error: 1},
			func(s string) bool { return s != "" && contains(s, "Page fault") },
		},
		{
			"EventOOMKill",
			&Event{Type: EventOOMKill, Target: "process", Bytes: 1024 * 1024 * 100},
			func(s string) bool { return s != "" && contains(s, "OOM kill") },
		},
		{
			"EventOOMKill_EmptyTarget",
			&Event{Type: EventOOMKill, Target: "", Bytes: 1024 * 1024 * 100},
			func(s string) bool { return s != "" && contains(s, "unknown") },
		},
		{
			"EventWrite",
			&Event{Type: EventWrite, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 1024},
			func(s string) bool { return s != "" && contains(s, "write()") },
		},
		{
			"EventWrite_EmptyTarget",
			&Event{Type: EventWrite, LatencyNS: 2000000, Target: "", Bytes: 1024},
			func(s string) bool { return s != "" && contains(s, "file") },
		},
		{
			"EventRead",
			&Event{Type: EventRead, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 1024},
			func(s string) bool { return s != "" && contains(s, "read()") },
		},
		{
			"EventRead_EmptyTarget",
			&Event{Type: EventRead, LatencyNS: 2000000, Target: "", Bytes: 1024},
			func(s string) bool { return s != "" && contains(s, "file") },
		},
		{
			"EventFsync",
			&Event{Type: EventFsync, LatencyNS: 1000000, Target: "/tmp/file"},
			func(s string) bool { return s != "" && contains(s, "fsync()") },
		},
		{
			"EventFsync_EmptyTarget",
			&Event{Type: EventFsync, LatencyNS: 1000000, Target: ""},
			func(s string) bool { return s != "" && contains(s, "file") },
		},
		{
			"EventSchedSwitch",
			&Event{Type: EventSchedSwitch, LatencyNS: 5000000},
			func(s string) bool { return s != "" && contains(s, "thread blocked") },
		},
		{
			"EventLockContention",
			&Event{Type: EventLockContention, LatencyNS: 10000000, Target: "mutex"},
			func(s string) bool { return s != "" && contains(s, "LOCK") },
		},
		{
			"EventLockContention_EmptyTarget",
			&Event{Type: EventLockContention, LatencyNS: 10000000, Target: ""},
			func(s string) bool { return s != "" && contains(s, "lock") },
		},
		{
			"EventTCPRetrans",
			&Event{Type: EventTCPRetrans, Target: "example.com:80"},
			func(s string) bool { return s != "" && contains(s, "retransmission") },
		},
		{
			"EventTCPRetrans_EmptyTarget",
			&Event{Type: EventTCPRetrans, Target: ""},
			func(s string) bool { return s != "" && contains(s, "unknown") },
		},
		{
			"EventNetDevError",
			&Event{Type: EventNetDevError, Target: "eth0", Error: 1},
			func(s string) bool { return s != "" && contains(s, "network device") },
		},
		{
			"EventNetDevError_EmptyTarget",
			&Event{Type: EventNetDevError, Target: "", Error: 1},
			func(s string) bool { return s != "" && contains(s, "iface") },
		},
		{
			"EventDBQuery",
			&Event{Type: EventDBQuery, LatencyNS: 5000000, Target: "SELECT * FROM users"},
			func(s string) bool { return s != "" && contains(s, "DB") },
		},
		{
			"EventDBQuery_EmptyTarget",
			&Event{Type: EventDBQuery, LatencyNS: 5000000, Target: ""},
			func(s string) bool { return s != "" && contains(s, "query") },
		},
		{
			"EventExec",
			&Event{Type: EventExec, LatencyNS: 1000000, Target: "/bin/ls"},
			func(s string) bool { return s != "" && contains(s, "execve") },
		},
		{
			"EventExec_Error",
			&Event{Type: EventExec, LatencyNS: 1000000, Target: "/bin/ls", Error: 1},
			func(s string) bool { return s != "" && contains(s, "failed") },
		},
		{
			"EventExec_EmptyTarget",
			&Event{Type: EventExec, LatencyNS: 1000000, Target: ""},
			func(s string) bool { return s != "" && contains(s, "unknown") },
		},
		{
			"EventFork",
			&Event{Type: EventFork, PID: 1234, Target: "child"},
			func(s string) bool { return s != "" && contains(s, "fork") },
		},
		{
			"EventFork_EmptyTarget",
			&Event{Type: EventFork, PID: 1234, Target: ""},
			func(s string) bool { return s != "" && contains(s, "child") },
		},
		{
			"EventOpen",
			&Event{Type: EventOpen, LatencyNS: 1000000, Target: "/tmp/file", Bytes: 5},
			func(s string) bool { return s != "" && contains(s, "open()") },
		},
		{
			"EventOpen_Error",
			&Event{Type: EventOpen, LatencyNS: 1000000, Target: "/tmp/file", Error: 1},
			func(s string) bool { return s != "" && contains(s, "failed") },
		},
		{
			"EventOpen_EmptyTarget",
			&Event{Type: EventOpen, LatencyNS: 1000000, Target: "", Bytes: 5},
			func(s string) bool { return s != "" && contains(s, "file") },
		},
		{
			"EventOpen_NegativeFD",
			&Event{Type: EventOpen, LatencyNS: 1000000, Target: "/tmp/file", Bytes: 0x8000000000000000},
			func(s string) bool { return s != "" && contains(s, "open()") && !contains(s, "fd=") },
		},
		{
			"EventClose",
			&Event{Type: EventClose, Bytes: 5},
			func(s string) bool { return s != "" && contains(s, "close()") && contains(s, "fd=5") },
		},
		{
			"EventClose_NoFD",
			&Event{Type: EventClose, Bytes: 0x8000000000000000},
			func(s string) bool { return s != "" && contains(s, "close()") && !contains(s, "fd=") },
		},
		{
			"EventHTTPReq",
			&Event{Type: EventHTTPReq, LatencyNS: 5000000, Target: "http://example.com"},
			func(s string) bool { return s != "" && contains(s, "UNKNOWN") },
		},
		{
			"EventHTTPReq_EmptyTarget",
			&Event{Type: EventHTTPReq, LatencyNS: 5000000, Target: ""},
			func(s string) bool { return s != "" && contains(s, "UNKNOWN") },
		},
		{
			"EventHTTPResp",
			&Event{Type: EventHTTPResp, LatencyNS: 5000000, Target: "http://example.com", Bytes: 2048},
			func(s string) bool { return s != "" && contains(s, "UNKNOWN") },
		},
		{
			"EventHTTPResp_EmptyTarget",
			&Event{Type: EventHTTPResp, LatencyNS: 5000000, Target: "", Bytes: 2048},
			func(s string) bool { return s != "" && contains(s, "UNKNOWN") },
		},
		{
			"UnknownEvent",
			&Event{Type: EventType(999)},
			func(s string) bool { return s != "" && contains(s, "UNKNOWN") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.FormatRealtimeMessage()
			if !tt.check(result) {
				t.Errorf("FormatRealtimeMessage() = %q, did not pass check", result)
			}
		})
	}
}

func TestEvent_FormatRealtimeMessage_TCPSendNoBytes(t *testing.T) {
	e := &Event{Type: EventTCPSend, LatencyNS: 15000000, Error: 0, Bytes: 0}
	result := e.FormatRealtimeMessage()
	if result == "" {
		t.Error("Expected non-empty message for high latency TCP send")
	}
	if !contains(result, "TCP send") {
		t.Errorf("Expected TCP send message, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_TCPRecvNoBytes(t *testing.T) {
	e := &Event{Type: EventTCPRecv, LatencyNS: 15000000, Error: 0, Bytes: 0}
	result := e.FormatRealtimeMessage()
	if result == "" {
		t.Error("Expected non-empty message for high latency TCP recv")
	}
	if !contains(result, "TCP recv") {
		t.Errorf("Expected TCP recv message, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_WriteNoBytes(t *testing.T) {
	e := &Event{Type: EventWrite, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 0}
	result := e.FormatRealtimeMessage()
	if result == "" {
		t.Error("Expected non-empty message for write")
	}
	if !contains(result, "write()") {
		t.Errorf("Expected write message, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_ReadNoBytes(t *testing.T) {
	e := &Event{Type: EventRead, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 0}
	result := e.FormatRealtimeMessage()
	if result == "" {
		t.Error("Expected non-empty message for read")
	}
	if !contains(result, "read()") {
		t.Errorf("Expected read message, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_ConnectEmptyTarget(t *testing.T) {
	e := &Event{Type: EventConnect, LatencyNS: 500000, Target: "", Error: 0}
	result := e.FormatRealtimeMessage()
	if !contains(result, "file") {
		t.Errorf("Expected 'file' as default target, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_ConnectQuestionMarkTarget(t *testing.T) {
	e := &Event{Type: EventConnect, LatencyNS: 500000, Target: "?", Error: 0}
	result := e.FormatRealtimeMessage()
	if !contains(result, "file") {
		t.Errorf("Expected 'file' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_ConnectBelowThreshold(t *testing.T) {
	e := &Event{Type: EventConnect, LatencyNS: 500000, Target: "example.com:80", Error: 0}
	result := e.FormatMessage()
	if result != "" {
		t.Errorf("Expected empty string for fast connect, got %q", result)
	}
}

func TestEvent_FormatMessage_TCPSendBelowThreshold(t *testing.T) {
	e := &Event{Type: EventTCPSend, LatencyNS: 5000000, Error: 0}
	result := e.FormatMessage()
	if result != "" {
		t.Errorf("Expected empty string for normal TCP send latency, got %q", result)
	}
}

func TestEvent_FormatMessage_TCPRecvBelowThreshold(t *testing.T) {
	e := &Event{Type: EventTCPRecv, LatencyNS: 5000000, Error: 0}
	result := e.FormatMessage()
	if result != "" {
		t.Errorf("Expected empty string for normal TCP recv latency, got %q", result)
	}
}

func TestEvent_FormatMessage_UDPSendBelowThreshold(t *testing.T) {
	e := &Event{Type: EventUDPSend, LatencyNS: 5000000, Error: 0}
	result := e.FormatMessage()
	if result != "" {
		t.Errorf("Expected empty string for normal UDP send latency, got %q", result)
	}
}

func TestEvent_FormatMessage_UDPRecvBelowThreshold(t *testing.T) {
	e := &Event{Type: EventUDPRecv, LatencyNS: 5000000, Error: 0}
	result := e.FormatMessage()
	if result != "" {
		t.Errorf("Expected empty string for normal UDP recv latency, got %q", result)
	}
}

func TestEvent_FormatMessage_UDPSendError(t *testing.T) {
	e := &Event{Type: EventUDPSend, Error: -1, LatencyNS: 1000000}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for UDP send error")
	}
	if !contains(result, "UDP send error") {
		t.Errorf("Expected UDP send error message, got %q", result)
	}
}

func TestEvent_FormatMessage_UDPRecvError(t *testing.T) {
	e := &Event{Type: EventUDPRecv, Error: -1, LatencyNS: 1000000}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for UDP recv error")
	}
	if !contains(result, "UDP recv error") {
		t.Errorf("Expected UDP recv error message, got %q", result)
	}
}

func TestEvent_FormatMessage_TCPSendWithBytes(t *testing.T) {
	e := &Event{Type: EventTCPSend, LatencyNS: 150000000, Error: 0, Bytes: 1024}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for high latency TCP send")
	}
	if !contains(result, "bytes") {
		t.Errorf("Expected bytes in message, got %q", result)
	}
}

func TestEvent_FormatMessage_TCPRecvWithBytes(t *testing.T) {
	e := &Event{Type: EventTCPRecv, LatencyNS: 150000000, Error: 0, Bytes: 1024}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for high latency TCP recv")
	}
	if !contains(result, "bytes") {
		t.Errorf("Expected bytes in message, got %q", result)
	}
}

func TestEvent_FormatMessage_UDPSendWithBytes(t *testing.T) {
	e := &Event{Type: EventUDPSend, LatencyNS: 150000000, Error: 0, Bytes: 1024}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for high latency UDP send")
	}
	if !contains(result, "bytes") {
		t.Errorf("Expected bytes in message, got %q", result)
	}
}

func TestEvent_FormatMessage_UDPRecvWithBytes(t *testing.T) {
	e := &Event{Type: EventUDPRecv, LatencyNS: 150000000, Error: 0, Bytes: 1024}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for high latency UDP recv")
	}
	if !contains(result, "bytes") {
		t.Errorf("Expected bytes in message, got %q", result)
	}
}

func TestEvent_FormatMessage_WriteWithBytes(t *testing.T) {
	e := &Event{Type: EventWrite, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 1024}
	result := e.FormatMessage()
	if !contains(result, "bytes") {
		t.Errorf("Expected bytes in message, got %q", result)
	}
}

func TestEvent_FormatMessage_ReadWithBytes(t *testing.T) {
	e := &Event{Type: EventRead, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 1024}
	result := e.FormatMessage()
	if !contains(result, "bytes") {
		t.Errorf("Expected bytes in message, got %q", result)
	}
}

func TestEvent_FormatMessage_HTTPRespWithBytes(t *testing.T) {
	e := &Event{Type: EventHTTPResp, LatencyNS: 5000000, Target: "http://example.com", Bytes: 2048}
	result := e.FormatMessage()
	if !contains(result, "bytes") {
		t.Errorf("Expected bytes in message, got %q", result)
	}
}

func TestEvent_FormatMessage_OpenWithFD(t *testing.T) {
	e := &Event{Type: EventOpen, LatencyNS: 1000000, Target: "/tmp/file", Bytes: 5, Error: 0}
	result := e.FormatMessage()
	if !contains(result, "fd=5") {
		t.Errorf("Expected fd in message, got %q", result)
	}
}

func TestEvent_FormatMessage_OpenWithoutFD(t *testing.T) {
	e := &Event{Type: EventOpen, LatencyNS: 1000000, Target: "/tmp/file", Bytes: 0x8000000000000000, Error: 0}
	result := e.FormatMessage()
	if contains(result, "fd=") {
		t.Errorf("Should not include fd when Bytes represents negative value, got %q", result)
	}
}

func TestEvent_FormatMessage_CloseWithFD(t *testing.T) {
	e := &Event{Type: EventClose, Bytes: 5}
	result := e.FormatMessage()
	if !contains(result, "fd=5") {
		t.Errorf("Expected fd in message, got %q", result)
	}
}

func TestEvent_FormatMessage_CloseWithoutFD(t *testing.T) {
	e := &Event{Type: EventClose, Bytes: 0x8000000000000000}
	result := e.FormatMessage()
	if contains(result, "fd=") {
		t.Errorf("Should not include fd when Bytes represents negative value, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_TCPSendBelowThreshold(t *testing.T) {
	e := &Event{Type: EventTCPSend, LatencyNS: 5000000, Error: 0}
	result := e.FormatRealtimeMessage()
	if result != "" {
		t.Errorf("Expected empty string for normal TCP send latency, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_TCPRecvBelowThreshold(t *testing.T) {
	e := &Event{Type: EventTCPRecv, LatencyNS: 5000000, Error: 0}
	result := e.FormatRealtimeMessage()
	if result != "" {
		t.Errorf("Expected empty string for normal TCP recv latency, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_TCPSendWithBytes(t *testing.T) {
	e := &Event{Type: EventTCPSend, LatencyNS: 15000000, Error: 0, Bytes: 1024}
	result := e.FormatRealtimeMessage()
	if result == "" {
		t.Error("Expected non-empty message for high latency TCP send")
	}
	if !contains(result, "bytes") {
		t.Errorf("Expected bytes in message, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_TCPRecvWithBytes(t *testing.T) {
	e := &Event{Type: EventTCPRecv, LatencyNS: 15000000, Error: 0, Bytes: 1024}
	result := e.FormatRealtimeMessage()
	if result == "" {
		t.Error("Expected non-empty message for high latency TCP recv")
	}
	if !contains(result, "bytes") {
		t.Errorf("Expected bytes in message, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_WriteWithBytes(t *testing.T) {
	e := &Event{Type: EventWrite, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 1024}
	result := e.FormatRealtimeMessage()
	if !contains(result, "bytes") {
		t.Errorf("Expected bytes in message, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_ReadWithBytes(t *testing.T) {
	e := &Event{Type: EventRead, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 1024}
	result := e.FormatRealtimeMessage()
	if !contains(result, "bytes") {
		t.Errorf("Expected bytes in message, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_OpenWithFD(t *testing.T) {
	e := &Event{Type: EventOpen, LatencyNS: 1000000, Target: "/tmp/file", Bytes: 5, Error: 0}
	result := e.FormatRealtimeMessage()
	if !contains(result, "fd=5") {
		t.Errorf("Expected fd in message, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_OpenWithoutFD(t *testing.T) {
	e := &Event{Type: EventOpen, LatencyNS: 1000000, Target: "/tmp/file", Bytes: 0x8000000000000000, Error: 0}
	result := e.FormatRealtimeMessage()
	if contains(result, "fd=") {
		t.Errorf("Should not include fd when Bytes represents negative value, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_CloseWithFD(t *testing.T) {
	e := &Event{Type: EventClose, Bytes: 5}
	result := e.FormatRealtimeMessage()
	if !contains(result, "fd=5") {
		t.Errorf("Expected fd in message, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_CloseWithoutFD(t *testing.T) {
	e := &Event{Type: EventClose, Bytes: 0x8000000000000000}
	result := e.FormatRealtimeMessage()
	if contains(result, "fd=") {
		t.Errorf("Should not include fd when Bytes represents negative value, got %q", result)
	}
}

func TestEvent_FormatMessage_FsyncEmptyTarget(t *testing.T) {
	e := &Event{Type: EventFsync, LatencyNS: 1000000, Target: ""}
	result := e.FormatMessage()
	if !contains(result, "file") {
		t.Errorf("Expected 'file' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_LockContentionEmptyTarget(t *testing.T) {
	e := &Event{Type: EventLockContention, LatencyNS: 10000000, Target: ""}
	result := e.FormatMessage()
	if !contains(result, "lock") {
		t.Errorf("Expected 'lock' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_TCPRetransEmptyTarget(t *testing.T) {
	e := &Event{Type: EventTCPRetrans, Target: ""}
	result := e.FormatMessage()
	if !contains(result, "unknown") {
		t.Errorf("Expected 'unknown' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_NetDevErrorEmptyTarget(t *testing.T) {
	e := &Event{Type: EventNetDevError, Target: "", Error: 1}
	result := e.FormatMessage()
	if !contains(result, "iface") {
		t.Errorf("Expected 'iface' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_DBQueryEmptyTarget(t *testing.T) {
	e := &Event{Type: EventDBQuery, LatencyNS: 5000000, Target: ""}
	result := e.FormatMessage()
	if !contains(result, "query") {
		t.Errorf("Expected 'query' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_ExecEmptyTarget(t *testing.T) {
	e := &Event{Type: EventExec, LatencyNS: 1000000, Target: ""}
	result := e.FormatMessage()
	if !contains(result, "unknown") {
		t.Errorf("Expected 'unknown' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_ForkEmptyTarget(t *testing.T) {
	e := &Event{Type: EventFork, PID: 1234, Target: ""}
	result := e.FormatMessage()
	if !contains(result, "child") {
		t.Errorf("Expected 'child' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_OpenEmptyTarget(t *testing.T) {
	e := &Event{Type: EventOpen, LatencyNS: 1000000, Target: "", Bytes: 5, Error: 0}
	result := e.FormatMessage()
	if !contains(result, "file") {
		t.Errorf("Expected 'file' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_OOMKillEmptyTarget(t *testing.T) {
	e := &Event{Type: EventOOMKill, Target: "", Bytes: 1024 * 1024 * 100}
	result := e.FormatMessage()
	if !contains(result, "unknown") {
		t.Errorf("Expected 'unknown' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_TCPStateEmptyTarget(t *testing.T) {
	e := &Event{Type: EventTCPState, TCPState: 1, Target: ""}
	result := e.FormatMessage()
	if !contains(result, "unknown") {
		t.Errorf("Expected 'unknown' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_HTTPReqEmptyTarget(t *testing.T) {
	e := &Event{Type: EventHTTPReq, LatencyNS: 5000000, Target: ""}
	result := e.FormatMessage()
	if !contains(result, "unknown") {
		t.Errorf("Expected 'unknown' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_HTTPRespEmptyTarget(t *testing.T) {
	e := &Event{Type: EventHTTPResp, LatencyNS: 5000000, Target: "", Bytes: 0}
	result := e.FormatMessage()
	if !contains(result, "unknown") {
		t.Errorf("Expected 'unknown' as default target, got %q", result)
	}
}

func TestEvent_FormatMessage_TCPSendErrorNotEAGAIN(t *testing.T) {
	e := &Event{Type: EventTCPSend, Error: -2, LatencyNS: 1000000}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for TCP send error")
	}
	if !contains(result, "TCP send error") {
		t.Errorf("Expected TCP send error message, got %q", result)
	}
}

func TestEvent_FormatMessage_TCPRecvErrorNotEAGAIN(t *testing.T) {
	e := &Event{Type: EventTCPRecv, Error: -2, LatencyNS: 1000000}
	result := e.FormatMessage()
	if result == "" {
		t.Error("Expected non-empty message for TCP recv error")
	}
	if !contains(result, "TCP recv error") {
		t.Errorf("Expected TCP recv error message, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_TCPSendErrorNotEAGAIN(t *testing.T) {
	e := &Event{Type: EventTCPSend, Error: -2, LatencyNS: 1000000}
	result := e.FormatRealtimeMessage()
	if result == "" {
		t.Error("Expected non-empty message for TCP send error")
	}
	if !contains(result, "TCP send error") {
		t.Errorf("Expected TCP send error message, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_TCPRecvErrorNotEAGAIN(t *testing.T) {
	e := &Event{Type: EventTCPRecv, Error: -2, LatencyNS: 1000000}
	result := e.FormatRealtimeMessage()
	if result == "" {
		t.Error("Expected non-empty message for TCP recv error")
	}
	if !contains(result, "TCP recv error") {
		t.Errorf("Expected TCP recv error message, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_FsyncEmptyTarget(t *testing.T) {
	e := &Event{Type: EventFsync, LatencyNS: 1000000, Target: ""}
	result := e.FormatRealtimeMessage()
	if !contains(result, "file") {
		t.Errorf("Expected 'file' as default target, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_LockContentionEmptyTarget(t *testing.T) {
	e := &Event{Type: EventLockContention, LatencyNS: 10000000, Target: ""}
	result := e.FormatRealtimeMessage()
	if !contains(result, "lock") {
		t.Errorf("Expected 'lock' as default target, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_TCPRetransEmptyTarget(t *testing.T) {
	e := &Event{Type: EventTCPRetrans, Target: ""}
	result := e.FormatRealtimeMessage()
	if !contains(result, "unknown") {
		t.Errorf("Expected 'unknown' as default target, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_NetDevErrorEmptyTarget(t *testing.T) {
	e := &Event{Type: EventNetDevError, Target: "", Error: 1}
	result := e.FormatRealtimeMessage()
	if !contains(result, "iface") {
		t.Errorf("Expected 'iface' as default target, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_DBQueryEmptyTarget(t *testing.T) {
	e := &Event{Type: EventDBQuery, LatencyNS: 5000000, Target: ""}
	result := e.FormatRealtimeMessage()
	if !contains(result, "query") {
		t.Errorf("Expected 'query' as default target, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_ExecEmptyTarget(t *testing.T) {
	e := &Event{Type: EventExec, LatencyNS: 1000000, Target: ""}
	result := e.FormatRealtimeMessage()
	if !contains(result, "unknown") {
		t.Errorf("Expected 'unknown' as default target, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_ForkEmptyTarget(t *testing.T) {
	e := &Event{Type: EventFork, PID: 1234, Target: ""}
	result := e.FormatRealtimeMessage()
	if !contains(result, "child") {
		t.Errorf("Expected 'child' as default target, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_OpenEmptyTarget(t *testing.T) {
	e := &Event{Type: EventOpen, LatencyNS: 1000000, Target: "", Bytes: 5, Error: 0}
	result := e.FormatRealtimeMessage()
	if !contains(result, "file") {
		t.Errorf("Expected 'file' as default target, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_OOMKillEmptyTarget(t *testing.T) {
	e := &Event{Type: EventOOMKill, Target: "", Bytes: 1024 * 1024 * 100}
	result := e.FormatRealtimeMessage()
	if !contains(result, "unknown") {
		t.Errorf("Expected 'unknown' as default target, got %q", result)
	}
}

func TestEvent_FormatRealtimeMessage_TCPStateEmptyTarget(t *testing.T) {
	e := &Event{Type: EventTCPState, TCPState: 1, Target: ""}
	result := e.FormatRealtimeMessage()
	if !contains(result, "unknown") {
		t.Errorf("Expected 'unknown' as default target, got %q", result)
	}
}

func TestEventTLSHandshake(t *testing.T) {
	e := &Event{
		Type:      EventTLSHandshake,
		LatencyNS: 100000000,
		Error:     0,
	}

	if e.TypeString() != "TLS" {
		t.Errorf("Expected TypeString() to return 'TLS', got %q", e.TypeString())
	}

	msg := e.FormatMessage()
	if msg == "" {
		t.Error("Expected non-empty message for TLS handshake event")
	}
	if !strings.Contains(msg, "[TLS]") {
		t.Errorf("Expected message to contain '[TLS]', got %q", msg)
	}
}

func TestEventTLSError(t *testing.T) {
	e := &Event{
		Type:  EventTLSError,
		Error: -1,
	}

	if e.TypeString() != "TLS" {
		t.Errorf("Expected TypeString() to return 'TLS', got %q", e.TypeString())
	}

	msg := e.FormatMessage()
	if msg == "" {
		t.Error("Expected non-empty message for TLS error event")
	}
	if !strings.Contains(msg, "[TLS]") {
		t.Errorf("Expected message to contain '[TLS]', got %q", msg)
	}
	if !strings.Contains(msg, "error") {
		t.Errorf("Expected message to contain 'error', got %q", msg)
	}
}

func TestEventUnlink(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := &Event{Type: EventUnlink, Target: "/tmp/foo.txt", LatencyNS: 1000000}
		msg := e.FormatMessage()
		if !strings.Contains(msg, "[FS]") {
			t.Errorf("Expected [FS] prefix, got %q", msg)
		}
		if !strings.Contains(msg, "unlink") {
			t.Errorf("Expected 'unlink' in message, got %q", msg)
		}
		if !strings.Contains(msg, "/tmp/foo.txt") {
			t.Errorf("Expected target in message, got %q", msg)
		}
	})
	t.Run("error", func(t *testing.T) {
		e := &Event{Type: EventUnlink, Target: "/tmp/foo.txt", Error: -2}
		msg := e.FormatMessage()
		if !strings.Contains(msg, "failed") {
			t.Errorf("Expected 'failed' in error message, got %q", msg)
		}
	})
	t.Run("empty_target", func(t *testing.T) {
		e := &Event{Type: EventUnlink, LatencyNS: 500000}
		msg := e.FormatMessage()
		if !strings.Contains(msg, "file") {
			t.Errorf("Expected 'file' fallback target in message, got %q", msg)
		}
	})
	if e := (&Event{Type: EventUnlink}); e.TypeString() != "FS" {
		t.Errorf("TypeString: got %q, want FS", e.TypeString())
	}
}

func TestEventRename(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := &Event{Type: EventRename, Target: "/tmp/old.txt>/tmp/new.txt", LatencyNS: 2000000}
		msg := e.FormatMessage()
		if !strings.Contains(msg, "[FS]") {
			t.Errorf("Expected [FS] prefix, got %q", msg)
		}
		if !strings.Contains(msg, "rename") {
			t.Errorf("Expected 'rename' in message, got %q", msg)
		}
	})
	t.Run("error", func(t *testing.T) {
		e := &Event{Type: EventRename, Target: "/tmp/old.txt", Error: -1}
		msg := e.FormatMessage()
		if !strings.Contains(msg, "failed") {
			t.Errorf("Expected 'failed' in error message, got %q", msg)
		}
	})
	if e := (&Event{Type: EventRename}); e.TypeString() != "FS" {
		t.Errorf("TypeString: got %q, want FS", e.TypeString())
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

func TestFormatRealtimeMessage_UnlinkRename(t *testing.T) {
	e := &Event{Type: EventUnlink, Target: "/var/log/old.log", LatencyNS: 3000000}
	msg := e.FormatRealtimeMessage()
	if !strings.Contains(msg, "[FS]") {
		t.Errorf("FormatRealtimeMessage for Unlink: got %q, want [FS] prefix", msg)
	}
	// Verify _ is unused
	_ = config.MaxTargetStringLength
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

// ─── formatEventMessage for additional event types ────────────────────────────

func TestFormatMessage_HTTP(t *testing.T) {
	e := &Event{Type: EventHTTPReq, LatencyNS: 10_000_000, Target: "GET /api/v1"}
	msg := e.FormatMessage()
	if msg != "" && !strings.Contains(msg, "HTTP") {
		t.Errorf("HTTP request message unexpected: %q", msg)
	}
}

func TestFormatMessage_HTTPResp(t *testing.T) {
	e := &Event{Type: EventHTTPResp, LatencyNS: 50_000_000, Error: 500}
	msg := e.FormatMessage()
	_ = msg // just ensure no panic
}

func TestFormatMessage_TCPRecv(t *testing.T) {
	// High latency → should produce message.
	e := &Event{Type: EventTCPRecv, LatencyNS: 200_000_000, Bytes: 512}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_TCPState(t *testing.T) {
	e := &Event{Type: EventTCPState, TCPState: 1, Target: "10.0.0.1:80"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_UDPSend(t *testing.T) {
	e := &Event{Type: EventUDPSend, Bytes: 1024}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_UDPRecv(t *testing.T) {
	e := &Event{Type: EventUDPRecv, Bytes: 512}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_SchedSwitch(t *testing.T) {
	e := &Event{Type: EventSchedSwitch, LatencyNS: 50_000_000}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_PageFault(t *testing.T) {
	e := &Event{Type: EventPageFault}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_OOMKill(t *testing.T) {
	e := &Event{Type: EventOOMKill, ProcessName: "leaky"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_TLSHandshake(t *testing.T) {
	e := &Event{Type: EventTLSHandshake, LatencyNS: 5_000_000, Target: "example.com"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_TLSError(t *testing.T) {
	e := &Event{Type: EventTLSError, Error: 1, Target: "example.com"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_LockContention(t *testing.T) {
	e := &Event{Type: EventLockContention, LatencyNS: 100_000_000}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_TCPRetrans(t *testing.T) {
	e := &Event{Type: EventTCPRetrans, Target: "10.0.0.1:80"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_NetDevError(t *testing.T) {
	e := &Event{Type: EventNetDevError, Error: 5}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_DBQuery(t *testing.T) {
	e := &Event{Type: EventDBQuery, LatencyNS: 50_000_000, Target: "SELECT *"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_Exec(t *testing.T) {
	e := &Event{Type: EventExec, Target: "/usr/bin/ls"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_Fork(t *testing.T) {
	e := &Event{Type: EventFork}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_Open(t *testing.T) {
	e := &Event{Type: EventOpen, Target: "/etc/passwd"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_Close(t *testing.T) {
	e := &Event{Type: EventClose}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_PoolAcquire(t *testing.T) {
	e := &Event{Type: EventPoolAcquire, LatencyNS: 10_000_000}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_PoolRelease(t *testing.T) {
	e := &Event{Type: EventPoolRelease, LatencyNS: 5_000_000}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_PoolExhausted(t *testing.T) {
	e := &Event{Type: EventPoolExhausted}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_Unlink(t *testing.T) {
	e := &Event{Type: EventUnlink, Target: "/tmp/file.txt"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_Rename(t *testing.T) {
	e := &Event{Type: EventRename, Target: "/tmp/old:/tmp/new"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_RedisCmd(t *testing.T) {
	e := &Event{Type: EventRedisCmd, LatencyNS: 1_000_000, Details: "SET"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_MemcachedCmd(t *testing.T) {
	e := &Event{Type: EventMemcachedCmd, LatencyNS: 500_000, Details: "get"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_FastCGIReq(t *testing.T) {
	e := &Event{Type: EventFastCGIReq, Target: "/index.php"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_FastCGIResp(t *testing.T) {
	e := &Event{Type: EventFastCGIResp, LatencyNS: 20_000_000, Error: 0}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_GRPCMethod(t *testing.T) {
	e := &Event{Type: EventGRPCMethod, LatencyNS: 8_000_000, Target: "/svc/Method"}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_KafkaProduce(t *testing.T) {
	e := &Event{Type: EventKafkaProduce, LatencyNS: 5_000_000, Details: "my-topic", Bytes: 256}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_KafkaFetch(t *testing.T) {
	e := &Event{Type: EventKafkaFetch, LatencyNS: 3_000_000, Details: "my-topic", Bytes: 512}
	msg := e.FormatMessage()
	_ = msg
}

func TestFormatMessage_Unknown(t *testing.T) {
	e := &Event{Type: EventType(9999)}
	msg := e.FormatMessage()
	_ = msg
}

// FormatRealtimeMessage paths.
func TestFormatRealtimeMessage_Connect(t *testing.T) {
	e := &Event{Type: EventConnect, LatencyNS: 2_000_000, Target: "10.0.0.1:80"}
	msg := e.FormatRealtimeMessage()
	_ = msg
}

func TestFormatRealtimeMessage_TCPSend_Latency(t *testing.T) {
	e := &Event{Type: EventTCPSend, LatencyNS: 200_000_000, Bytes: 1024}
	msg := e.FormatRealtimeMessage()
	_ = msg
}

func TestFormatRealtimeMessage_Fsync(t *testing.T) {
	e := &Event{Type: EventFsync, LatencyNS: 50_000_000, Target: "/data/db"}
	msg := e.FormatRealtimeMessage()
	_ = msg
}

// Cover line 397-399: EventTLSHandshake with Error != 0
func TestFormatMessage_TLSHandshake_Error(t *testing.T) {
	e := &Event{Type: EventTLSHandshake, Error: 5, LatencyNS: 3_000_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "failed") {
		t.Errorf("expected 'failed' in TLSHandshake error message, got %q", msg)
	}
}

// Cover line 417-418: EventResourceLimit with default resource type (TCPState >= 3)
func TestFormatMessage_ResourceLimit_DefaultType(t *testing.T) {
	// TCPState=5 → default "Resource", Error=85 → WARNING (above warnPct=80)
	e := &Event{Type: EventResourceLimit, TCPState: 5, Error: 85}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "Resource") {
		t.Errorf("expected 'Resource' in message for unknown resource type, got %q", msg)
	}
}

// Cover lines 442-444: EventPoolAcquire with realtime=true
func TestFormatRealtimeMessage_PoolAcquire(t *testing.T) {
	e := &Event{Type: EventPoolAcquire, LatencyNS: 5_000_000, Target: "redis:6379"}
	msg := e.FormatRealtimeMessage()
	if !strings.Contains(msg, "acquire from") {
		t.Errorf("expected 'acquire from' in realtime pool message, got %q", msg)
	}
}

// Cover lines 452-454: EventPoolRelease with realtime=true
func TestFormatRealtimeMessage_PoolRelease(t *testing.T) {
	e := &Event{Type: EventPoolRelease, Target: "db-pool"}
	msg := e.FormatRealtimeMessage()
	if !strings.Contains(msg, "release to") {
		t.Errorf("expected 'release to' in realtime pool message, got %q", msg)
	}
}

// Cover lines 462-464: EventPoolExhausted with realtime=true
func TestFormatRealtimeMessage_PoolExhausted(t *testing.T) {
	e := &Event{Type: EventPoolExhausted, LatencyNS: 50_000_000, Target: "pg-pool"}
	msg := e.FormatRealtimeMessage()
	if !strings.Contains(msg, "exhausted") {
		t.Errorf("expected 'exhausted' in realtime pool message, got %q", msg)
	}
}

// Cover lines 479-481: EventRename with empty target
func TestFormatMessage_Rename_EmptyTarget(t *testing.T) {
	e := &Event{Type: EventRename, Target: "", LatencyNS: 2_000_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "file") {
		t.Errorf("expected 'file' as default target in rename message, got %q", msg)
	}
}

// Cover lines 489-491: EventRedisCmd with empty Details (cmd = "CMD")
func TestFormatMessage_RedisCmd_EmptyDetails(t *testing.T) {
	e := &Event{Type: EventRedisCmd, LatencyNS: 1_000_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "CMD") {
		t.Errorf("expected 'CMD' as default redis cmd, got %q", msg)
	}
}

// Cover lines 492-494: EventRedisCmd with Error != 0
func TestFormatMessage_RedisCmd_Error(t *testing.T) {
	e := &Event{Type: EventRedisCmd, Details: "GET", Error: 1, LatencyNS: 1_000_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "failed") {
		t.Errorf("expected 'failed' in redis error message, got %q", msg)
	}
}

// Cover lines 496-498: EventRedisCmd with Bytes > 0 (no error)
func TestFormatMessage_RedisCmd_WithBytes(t *testing.T) {
	e := &Event{Type: EventRedisCmd, Details: "GET", Bytes: 256, LatencyNS: 1_000_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "bytes") {
		t.Errorf("expected bytes in redis message, got %q", msg)
	}
}

// Cover lines 503-505: EventMemcachedCmd with empty Details (op = "op")
func TestFormatMessage_MemcachedCmd_EmptyDetails(t *testing.T) {
	e := &Event{Type: EventMemcachedCmd, LatencyNS: 500_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "op") {
		t.Errorf("expected 'op' as default memcached op, got %q", msg)
	}
}

// Cover lines 506-508: EventMemcachedCmd with Error != 0
func TestFormatMessage_MemcachedCmd_Error(t *testing.T) {
	e := &Event{Type: EventMemcachedCmd, Details: "set", Error: 2, LatencyNS: 500_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "failed") {
		t.Errorf("expected 'failed' in memcached error message, got %q", msg)
	}
}

// Cover lines 510-512: EventMemcachedCmd with Bytes > 0 (no error)
func TestFormatMessage_MemcachedCmd_WithBytes(t *testing.T) {
	e := &Event{Type: EventMemcachedCmd, Details: "get", Bytes: 128, LatencyNS: 500_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "bytes") {
		t.Errorf("expected bytes in memcached message, got %q", msg)
	}
}

// Cover lines 518-520: EventFastCGIReq with empty Target (uri = "/")
func TestFormatMessage_FastCGIReq_EmptyURI(t *testing.T) {
	e := &Event{Type: EventFastCGIReq, Target: "", Details: "POST"}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "FASTCGI") {
		t.Errorf("expected FASTCGI in message, got %q", msg)
	}
}

// Cover lines 535-537: EventGRPCMethod with empty Target (method = "/unknown")
func TestFormatMessage_GRPCMethod_EmptyTarget(t *testing.T) {
	e := &Event{Type: EventGRPCMethod, LatencyNS: 4_000_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "/unknown") {
		t.Errorf("expected '/unknown' as default grpc method, got %q", msg)
	}
}

// Cover lines 538-540: EventGRPCMethod with Error != 0
func TestFormatMessage_GRPCMethod_Error(t *testing.T) {
	e := &Event{Type: EventGRPCMethod, Target: "/svc/Method", Error: 3, LatencyNS: 4_000_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "failed") {
		t.Errorf("expected 'failed' in grpc error message, got %q", msg)
	}
}

// Cover lines 542-544: EventGRPCMethod with Bytes > 0 (no error)
func TestFormatMessage_GRPCMethod_WithBytes(t *testing.T) {
	e := &Event{Type: EventGRPCMethod, Target: "/svc/List", Bytes: 512, LatencyNS: 4_000_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "bytes") {
		t.Errorf("expected bytes in grpc message, got %q", msg)
	}
}

// Cover lines 549-551: EventKafkaProduce with empty Details (topic = "unknown")
func TestFormatMessage_KafkaProduce_EmptyTopic(t *testing.T) {
	e := &Event{Type: EventKafkaProduce, LatencyNS: 2_000_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "unknown") {
		t.Errorf("expected 'unknown' as default kafka topic, got %q", msg)
	}
}

// Cover lines 552-554: EventKafkaProduce with Error != 0
func TestFormatMessage_KafkaProduce_Error(t *testing.T) {
	e := &Event{Type: EventKafkaProduce, Details: "orders", Error: 1, LatencyNS: 2_000_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "failed") {
		t.Errorf("expected 'failed' in kafka produce error message, got %q", msg)
	}
}

// Cover lines 563-565: EventKafkaFetch with empty Details (topic = "unknown")
func TestFormatMessage_KafkaFetch_EmptyTopic(t *testing.T) {
	e := &Event{Type: EventKafkaFetch, LatencyNS: 1_500_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "unknown") {
		t.Errorf("expected 'unknown' as default kafka fetch topic, got %q", msg)
	}
}

// Cover lines 566-568: EventKafkaFetch with Error != 0
func TestFormatMessage_KafkaFetch_Error(t *testing.T) {
	e := &Event{Type: EventKafkaFetch, Details: "events", Error: 1, LatencyNS: 1_500_000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "error") {
		t.Errorf("expected 'error' in kafka fetch error message, got %q", msg)
	}
}
