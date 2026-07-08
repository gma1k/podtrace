package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"testing"
	"unsafe"

	"github.com/podtrace/podtrace/internal/events"
)

// testRawV8 mirrors the on-wire struct event layout including the V8
// correlation_id field.
type testRawV8 struct {
	Timestamp     uint64
	PID           uint32
	Type          uint32
	LatencyNS     uint64
	Error         int32
	_             uint32
	Bytes         uint64
	TCPState      uint32
	_             uint32
	StackKey      uint64
	CgroupID      uint64
	Comm          [16]byte
	Target        [128]byte
	Details       [128]byte
	NetNsID       uint32
	_             uint32
	DNSServerIP   uint32
	DNSTransport  uint8
	_             [3]uint8
	DNSServerIP6  [16]byte
	PeerSaddr     uint32
	PeerDaddr     uint32
	PeerSport     uint16
	PeerDport     uint16
	PeerFamily    uint8
	_             [3]uint8
	PeerSaddr6    [16]byte
	PeerDaddr6    [16]byte
	CorrelationID uint64
}

// TestParseEvent_V8_CorrelationID asserts the V8 record decodes correlation_id
// and still fills the V7 peer 4-tuple.
func TestParseEvent_V8_CorrelationID(t *testing.T) {
	if got := int(unsafe.Sizeof(testRawV8{})); got != 424 {
		t.Fatalf("testRawV8 size = %d, want 424 (must match C sizeof(struct event))", got)
	}
	var raw testRawV8
	raw.Timestamp = 111
	raw.PID = 42
	raw.Type = uint32(events.EventHTTPResp)
	raw.LatencyNS = 5_000_000
	raw.PeerFamily = 2 // AF_INET
	raw.PeerSport = 8080
	raw.PeerDport = 54321
	binary.LittleEndian.PutUint32(raw.PeerSaddr6[:4], 0) // v4 uses PeerSaddr
	raw.PeerSaddr = 0x0100007f                           // 127.0.0.1
	raw.PeerDaddr = 0x0100007f
	raw.CorrelationID = 0xDEADBEEF12345678

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	event := ParseEvent(buf.Bytes())
	if event == nil {
		t.Fatal("ParseEvent returned nil for a V8 record")
	}
	if event.CorrelationID != raw.CorrelationID {
		t.Errorf("CorrelationID = %#x, want %#x", event.CorrelationID, raw.CorrelationID)
	}
	if event.PeerDstPort != raw.PeerDport {
		t.Errorf("PeerDstPort = %d, want %d (V8 path not taken?)", event.PeerDstPort, raw.PeerDport)
	}
}

func TestParseEvent_ValidEvent(t *testing.T) {
	var raw rawEvent
	raw.Timestamp = 1234567890
	raw.PID = 1234
	raw.Type = uint32(events.EventDNS)
	raw.LatencyNS = 5000000 // 5ms
	raw.Error = 0
	raw.Bytes = 1024
	raw.TCPState = 0
	raw.StackKey = 0
	copy(raw.Target[:], "example.com")
	copy(raw.Details[:], "details")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("Failed to write binary data: %v", err)
	}

	event := ParseEvent(buf.Bytes())
	if event == nil {
		t.Fatal("ParseEvent returned nil for valid event")
	}

	if event.Timestamp != raw.Timestamp {
		t.Errorf("Expected timestamp %d, got %d", raw.Timestamp, event.Timestamp)
	}
	if event.PID != raw.PID {
		t.Errorf("Expected PID %d, got %d", raw.PID, event.PID)
	}
	if event.CgroupID != 0 {
		t.Errorf("Expected cgroup ID 0 for v1 event, got %d", event.CgroupID)
	}
	if event.Type != events.EventType(raw.Type) {
		t.Errorf("Expected type %d, got %d", raw.Type, event.Type)
	}
	if event.LatencyNS != raw.LatencyNS {
		t.Errorf("Expected latency %d, got %d", raw.LatencyNS, event.LatencyNS)
	}
	if event.Error != raw.Error {
		t.Errorf("Expected error %d, got %d", raw.Error, event.Error)
	}
	if event.Bytes != raw.Bytes {
		t.Errorf("Expected bytes %d, got %d", raw.Bytes, event.Bytes)
	}
	if event.Target != "example.com" {
		t.Errorf("Expected target 'example.com', got '%s'", event.Target)
	}
}

func TestParseEvent_ValidEventV2_WithCgroupID(t *testing.T) {
	type rawEventV2 struct {
		Timestamp uint64
		PID       uint32
		Type      uint32
		LatencyNS uint64
		Error     int32
		_         uint32
		Bytes     uint64
		TCPState  uint32
		_         uint32
		StackKey  uint64
		CgroupID  uint64
		Target    [128]byte
		Details   [128]byte
	}

	var raw rawEventV2
	raw.Timestamp = 1234567890
	raw.PID = 1234
	raw.Type = uint32(events.EventDNS)
	raw.LatencyNS = 5000000
	raw.Error = 0
	raw.Bytes = 1024
	raw.TCPState = 0
	raw.StackKey = 0
	raw.CgroupID = 0x1122334455667788
	copy(raw.Target[:], "example.com")
	copy(raw.Details[:], "details")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("Failed to write binary data: %v", err)
	}

	event := ParseEvent(buf.Bytes())
	if event == nil {
		t.Fatal("ParseEvent returned nil for valid v2 event")
	}
	if event.CgroupID != raw.CgroupID {
		t.Errorf("Expected cgroup ID %d, got %d", raw.CgroupID, event.CgroupID)
	}
}

func TestParseEvent_TooSmall(t *testing.T) {
	data := make([]byte, 10) // Too small
	event := ParseEvent(data)
	if event != nil {
		t.Error("ParseEvent should return nil for data that's too small")
	}
}

func TestParseEvent_EmptyData(t *testing.T) {
	event := ParseEvent([]byte{})
	if event != nil {
		t.Error("ParseEvent should return nil for empty data")
	}
}

func TestParseEvent_NilData(t *testing.T) {
	event := ParseEvent(nil)
	if event != nil {
		t.Error("ParseEvent should return nil for nil data")
	}
}

func TestParseEvent_AllEventTypes(t *testing.T) {
	eventTypes := []events.EventType{
		events.EventDNS,
		events.EventConnect,
		events.EventTCPSend,
		events.EventTCPRecv,
		events.EventWrite,
		events.EventRead,
		events.EventFsync,
		events.EventSchedSwitch,
		events.EventTCPState,
		events.EventPageFault,
		events.EventOOMKill,
		events.EventUDPSend,
		events.EventUDPRecv,
		events.EventHTTPReq,
		events.EventHTTPResp,
		events.EventLockContention,
		events.EventTCPRetrans,
		events.EventNetDevError,
		events.EventDBQuery,
		events.EventExec,
		events.EventFork,
		events.EventOpen,
		events.EventClose,
		events.EventTLSHandshake,
		events.EventTLSError,
		events.EventResourceLimit,
		events.EventPoolAcquire,
		events.EventPoolRelease,
		events.EventPoolExhausted,
		events.EventUnlink,
		events.EventRename,
	}

	for i, et := range eventTypes {
		t.Run(fmt.Sprintf("EventType_%d", i), func(t *testing.T) {
			var raw rawEvent
			raw.Type = uint32(et)
			raw.PID = 1
			raw.Timestamp = 1000

			var buf bytes.Buffer
			if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
				t.Fatalf("Failed to write binary data: %v", err)
			}

			event := ParseEvent(buf.Bytes())
			if event == nil {
				t.Fatalf("ParseEvent returned nil for event type %d", et)
			}
			if event.Type != et {
				t.Errorf("Expected type %d, got %d", et, event.Type)
			}
		})
	}
}

func TestParseEvent_TargetTruncation(t *testing.T) {
	var raw rawEvent
	longTarget := make([]byte, 200)
	for i := range longTarget {
		longTarget[i] = 'a'
	}
	copy(raw.Target[:], longTarget)

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("Failed to write binary data: %v", err)
	}

	event := ParseEvent(buf.Bytes())
	if event == nil {
		t.Fatal("ParseEvent returned nil")
	}
	if len(event.Target) > 128 {
		t.Errorf("Target should be truncated to 128 bytes, got %d", len(event.Target))
	}
}

func TestParseEvent_NullTerminatedStrings(t *testing.T) {
	var raw rawEvent
	copy(raw.Target[:], []byte("test\x00\x00\x00"))
	copy(raw.Details[:], []byte("details\x00\x00"))

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("Failed to write binary data: %v", err)
	}

	event := ParseEvent(buf.Bytes())
	if event == nil {
		t.Fatal("ParseEvent returned nil")
	}
	// bytes.TrimRight removes trailing nulls only
	if event.Target != "test" {
		t.Errorf("Expected target 'test', got '%s'", event.Target)
	}
	if event.Details != "details" {
		t.Errorf("Expected details 'details', got '%s'", event.Details)
	}
}

func TestParseEvent_BinaryReadError(t *testing.T) {
	orig := binaryRead
	t.Cleanup(func() { binaryRead = orig })

	binaryRead = func(r io.Reader, order binary.ByteOrder, data interface{}) error {
		return fmt.Errorf("forced error")
	}

	data := make([]byte, int(unsafe.Sizeof(rawEvent{})))
	if ev := ParseEvent(data); ev != nil {
		t.Fatalf("expected nil event on binary read error, got %#v", ev)
	}
}

func TestPutEvent_NilEvent(t *testing.T) {
	PutEvent(nil)
}

func TestPutEvent_ValidEvent(t *testing.T) {
	event := &events.Event{
		Timestamp:   1234567890,
		PID:         1234,
		Type:        events.EventDNS,
		LatencyNS:   5000000,
		Error:       0,
		Bytes:       1024,
		TCPState:    0,
		StackKey:    0,
		Target:      "example.com",
		Details:     "details",
		ProcessName: "test-process",
		Stack:       []uint64{0x1234, 0x5678},
	}

	PutEvent(event)

	if event.Stack != nil {
		t.Error("PutEvent should set Stack to nil")
	}
	if event.ProcessName != "" {
		t.Error("PutEvent should set ProcessName to empty string")
	}
	if event.Target != "" {
		t.Error("PutEvent should set Target to empty string")
	}
	if event.Details != "" {
		t.Error("PutEvent should set Details to empty string")
	}
}

func TestPutEvent_EventReuse(t *testing.T) {
	var raw rawEvent
	raw.Timestamp = 1234567890
	raw.PID = 1234
	raw.Type = uint32(events.EventDNS)
	copy(raw.Target[:], "first-event.com")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("Failed to write binary data: %v", err)
	}

	event1 := ParseEvent(buf.Bytes())
	if event1 == nil {
		t.Fatal("ParseEvent returned nil")
	}

	PutEvent(event1)

	var raw2 rawEvent
	raw2.Timestamp = 9876543210
	raw2.PID = 5678
	raw2.Type = uint32(events.EventConnect)
	copy(raw2.Target[:], "second-event.com")

	buf.Reset()
	if err := binary.Write(&buf, binary.LittleEndian, raw2); err != nil {
		t.Fatalf("Failed to write binary data: %v", err)
	}

	event2 := ParseEvent(buf.Bytes())
	if event2 == nil {
		t.Fatal("ParseEvent returned nil")
	}

	if event1 == event2 {
		t.Log("PutEvent allows event reuse from pool")
	}
}

func TestParseEvent_ValidEventV3_WithComm(t *testing.T) {
	// rawEventV3 includes CgroupID + Comm fields beyond V2.
	type rawEventV3 struct {
		Timestamp uint64
		PID       uint32
		Type      uint32
		LatencyNS uint64
		Error     int32
		_         uint32
		Bytes     uint64
		TCPState  uint32
		_         uint32
		StackKey  uint64
		CgroupID  uint64
		Comm      [16]byte
		Target    [128]byte
		Details   [128]byte
	}

	var raw rawEventV3
	raw.Timestamp = 9999
	raw.PID = 42
	raw.Type = uint32(events.EventTCPSend)
	raw.LatencyNS = 1000
	raw.CgroupID = 0xdeadbeef
	copy(raw.Comm[:], "myprocess\x00")
	copy(raw.Target[:], "10.0.0.1:80")
	copy(raw.Details[:], "v3-detail")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}

	event := ParseEvent(buf.Bytes())
	if event == nil {
		t.Fatal("ParseEvent returned nil for V3 event")
	}
	if event.CgroupID != raw.CgroupID {
		t.Errorf("CgroupID: got %d, want %d", event.CgroupID, raw.CgroupID)
	}
	if event.ProcessName != "myprocess" {
		t.Errorf("ProcessName: got %q, want %q", event.ProcessName, "myprocess")
	}
	if event.Target != "10.0.0.1:80" {
		t.Errorf("Target: got %q, want %q", event.Target, "10.0.0.1:80")
	}
}

func TestParseEvent_BinaryReadError_V2Path(t *testing.T) {
	orig := binaryRead
	t.Cleanup(func() { binaryRead = orig })

	// Count calls: error only on second call (V2 branch) — but since we use exact V2 size,
	// only V2 branch runs and its binaryRead is the first call.
	callCount := 0
	binaryRead = func(r io.Reader, order binary.ByteOrder, data interface{}) error {
		callCount++
		return fmt.Errorf("forced V2 error")
	}

	// Create V2-sized data.
	type rawEventV2 struct {
		Timestamp uint64
		PID       uint32
		Type      uint32
		LatencyNS uint64
		Error     int32
		_         uint32
		Bytes     uint64
		TCPState  uint32
		_         uint32
		StackKey  uint64
		CgroupID  uint64
		Target    [128]byte
		Details   [128]byte
	}
	data := make([]byte, int(unsafe.Sizeof(rawEventV2{})))
	if ev := ParseEvent(data); ev != nil {
		t.Fatalf("expected nil event on V2 binary read error")
	}
}

func TestParseEvent_ValidEventV4_WithNetNsID(t *testing.T) {
	type rawEventV4 struct {
		Timestamp uint64
		PID       uint32
		Type      uint32
		LatencyNS uint64
		Error     int32
		_         uint32
		Bytes     uint64
		TCPState  uint32
		_         uint32
		StackKey  uint64
		CgroupID  uint64
		Comm      [16]byte
		Target    [128]byte
		Details   [128]byte
		NetNsID   uint32
		_         uint32
	}

	var raw rawEventV4
	raw.Timestamp = 777
	raw.PID = 99
	raw.Type = uint32(events.EventConnect)
	raw.LatencyNS = 2000
	raw.CgroupID = 0xabcdef01
	raw.NetNsID = 0x12345678
	copy(raw.Comm[:], "svcworker\x00")
	copy(raw.Target[:], "192.168.1.1:443")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}

	event := ParseEvent(buf.Bytes())
	if event == nil {
		t.Fatal("ParseEvent returned nil for V4 event")
	}
	if event.NetNsID != raw.NetNsID {
		t.Errorf("NetNsID: got %d, want %d", event.NetNsID, raw.NetNsID)
	}
	if event.CgroupID != raw.CgroupID {
		t.Errorf("CgroupID: got %d, want %d", event.CgroupID, raw.CgroupID)
	}
	if event.ProcessName != "svcworker" {
		t.Errorf("ProcessName: got %q, want %q", event.ProcessName, "svcworker")
	}
}

func TestParseEvent_EventUnlink_EventRename(t *testing.T) {
	for _, et := range []events.EventType{events.EventUnlink, events.EventRename} {
		t.Run(fmt.Sprintf("EventType_%d", et), func(t *testing.T) {
			var raw rawEvent
			raw.Type = uint32(et)
			raw.PID = 5
			raw.Timestamp = 100
			copy(raw.Target[:], "/tmp/testfile")

			var buf bytes.Buffer
			if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
				t.Fatalf("binary.Write: %v", err)
			}

			event := ParseEvent(buf.Bytes())
			if event == nil {
				t.Fatalf("ParseEvent returned nil for %v", et)
			}
			if event.Type != et {
				t.Errorf("Type: got %v, want %v", event.Type, et)
			}
			if event.Target != "/tmp/testfile" {
				t.Errorf("Target: got %q, want /tmp/testfile", event.Target)
			}
		})
	}
}

func TestParseEvent_BinaryReadError_V3Path(t *testing.T) {
	orig := binaryRead
	t.Cleanup(func() { binaryRead = orig })

	binaryRead = func(r io.Reader, order binary.ByteOrder, data interface{}) error {
		return fmt.Errorf("forced V3 error")
	}

	// Create V3-sized data.
	type rawEventV3 struct {
		Timestamp uint64
		PID       uint32
		Type      uint32
		LatencyNS uint64
		Error     int32
		_         uint32
		Bytes     uint64
		TCPState  uint32
		_         uint32
		StackKey  uint64
		CgroupID  uint64
		Comm      [16]byte
		Target    [128]byte
		Details   [128]byte
	}
	data := make([]byte, int(unsafe.Sizeof(rawEventV3{})))
	if ev := ParseEvent(data); ev != nil {
		t.Fatalf("expected nil event on V3 binary read error")
	}
}

func BenchmarkParseEvent(b *testing.B) {
	var raw rawEvent
	raw.Timestamp = 1234567890
	raw.PID = 1234
	raw.Type = uint32(events.EventDNS)
	raw.LatencyNS = 5000000
	copy(raw.Target[:], "example.com")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		b.Fatalf("Failed to write binary data: %v", err)
	}
	eventData := buf.Bytes()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseEvent(eventData)
	}
}

func TestParseEvent_V5_DNSFields(t *testing.T) {
	// Mirror of the V5 wire layout (rawEventV5 is local to ParseEvent).
	type rawV5 struct {
		Timestamp    uint64
		PID          uint32
		Type         uint32
		LatencyNS    uint64
		Error        int32
		_            uint32
		Bytes        uint64
		TCPState     uint32
		_            uint32
		StackKey     uint64
		CgroupID     uint64
		Comm         [16]byte
		Target       [128]byte
		Details      [128]byte
		NetNsID      uint32
		_            uint32
		DNSServerIP  uint32
		DNSTransport uint8
		_            [3]uint8
	}
	var raw rawV5
	raw.Type = uint32(events.EventDNS)
	raw.TCPState = 28 // AAAA
	raw.Error = 3     // NXDOMAIN
	raw.DNSServerIP = 0x0a00600a
	raw.DNSTransport = 1 // TCP
	copy(raw.Target[:], "example.com")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatal(err)
	}
	e := ParseEvent(buf.Bytes())
	if e == nil {
		t.Fatal("ParseEvent returned nil for V5 event")
	}
	if e.DNSServerIP != 0x0a00600a {
		t.Errorf("DNSServerIP = %#x, want 0x0a00600a", e.DNSServerIP)
	}
	if e.DNSTransport != 1 {
		t.Errorf("DNSTransport = %d, want 1", e.DNSTransport)
	}
	if e.TCPState != 28 || e.Error != 3 || e.Target != "example.com" {
		t.Errorf("unexpected decode: qtype=%d rcode=%d target=%q", e.TCPState, e.Error, e.Target)
	}
}

func TestParseEvent_V6_DNSServerIP6(t *testing.T) {
	type rawV6 struct {
		Timestamp    uint64
		PID          uint32
		Type         uint32
		LatencyNS    uint64
		Error        int32
		_            uint32
		Bytes        uint64
		TCPState     uint32
		_            uint32
		StackKey     uint64
		CgroupID     uint64
		Comm         [16]byte
		Target       [128]byte
		Details      [128]byte
		NetNsID      uint32
		_            uint32
		DNSServerIP  uint32
		DNSTransport uint8
		_            [3]uint8
		DNSServerIP6 [16]byte
	}
	var raw rawV6
	raw.Type = uint32(events.EventDNS)
	raw.TCPState = 28 // AAAA
	copy(raw.Target[:], "example.com")
	// 2606:4700:4700::1111 (Cloudflare)
	want := [16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11}
	raw.DNSServerIP6 = want

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatal(err)
	}
	e := ParseEvent(buf.Bytes())
	if e == nil {
		t.Fatal("ParseEvent returned nil for V6 event")
	}
	if e.DNSServerIP6 != want {
		t.Errorf("DNSServerIP6 = %v, want %v", e.DNSServerIP6, want)
	}
	if got := e.DNSServerAddr(); got != "2606:4700:4700:0000:0000:0000:0000:1111" {
		t.Errorf("DNSServerAddr = %q", got)
	}
}

// TestParseEvent_HTTPSocketEndpoint exercises the socket-level HTTP/1.x path
// end-to-end through the parser: the request line lands in Target ("METHOD
// path") and the response status code in Details, and both survive parsing
// and surface in the formatted message.
func TestParseEvent_HTTPSocketEndpoint(t *testing.T) {
	var raw rawEvent
	raw.Timestamp = 42
	raw.PID = 99
	raw.Type = uint32(events.EventHTTPResp)
	raw.LatencyNS = 5000000 // 5ms
	raw.Error = 503
	raw.Bytes = 2048
	copy(raw.Target[:], "GET /api/users")
	copy(raw.Details[:], "503")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	event := ParseEvent(buf.Bytes())
	if event == nil {
		t.Fatal("ParseEvent returned nil")
	}
	if event.Target != "GET /api/users" {
		t.Errorf("Target = %q, want \"GET /api/users\"", event.Target)
	}
	if event.Details != "503" {
		t.Errorf("Details = %q, want \"503\"", event.Details)
	}
	msg := event.FormatMessage()
	if !strings.Contains(msg, "GET /api/users") || !strings.Contains(msg, "503") {
		t.Errorf("formatted message %q missing endpoint or status", msg)
	}
}
