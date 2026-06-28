package parser

import (
	"encoding/binary"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

// TestParseEventPeerV7 locks the rawEventV7 ABI: a 416-byte event with the peer
// 4-tuple at offsets 368.. must decode into events.Event peer fields.
func TestParseEventPeerV7(t *testing.T) {
	const size = 416
	data := make([]byte, size)
	binary.LittleEndian.PutUint32(data[12:16], uint32(events.EventHTTPReq)) // Type
	// peer block (pahole: saddr@368 daddr@372 sport@376 dport@378 family@380)
	binary.LittleEndian.PutUint32(data[368:372], 0xC0A80005) // 192.168.0.5
	binary.LittleEndian.PutUint32(data[372:376], 0xC0A80001) // 192.168.0.1
	binary.LittleEndian.PutUint16(data[376:378], 40000)      // sport
	binary.LittleEndian.PutUint16(data[378:380], 443)        // dport
	data[380] = 2                                            // AF_INET

	ev := ParseEvent(data)
	if ev == nil {
		t.Fatal("ParseEvent returned nil")
	}
	if ev.PeerSrcIP != "192.168.0.5" || ev.PeerDstIP != "192.168.0.1" {
		t.Errorf("peer IPs = %q -> %q, want 192.168.0.5 -> 192.168.0.1", ev.PeerSrcIP, ev.PeerDstIP)
	}
	if ev.PeerSrcPort != 40000 || ev.PeerDstPort != 443 {
		t.Errorf("peer ports = %d -> %d, want 40000 -> 443", ev.PeerSrcPort, ev.PeerDstPort)
	}
}
