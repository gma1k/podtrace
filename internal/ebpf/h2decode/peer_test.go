package h2decode

import (
	"encoding/binary"
	"testing"
)

// TestParseRecordPeer verifies the L7<->L4 peer 4-tuple is decoded from the
// fixed header (offsets 48..96 of struct h2_hdr_record).
func TestParseRecordPeer(t *testing.T) {
	data := make([]byte, recordHeaderSize)        // 96, no frag
	binary.LittleEndian.PutUint16(data[36:38], 0) // frag_len = 0
	data[38] = DirIngress                         // direction
	// peer: AF_INET, src 10.0.0.1:54321 -> dst 10.0.0.2:8443
	binary.LittleEndian.PutUint32(data[48:52], 0x0A000001) // saddr 10.0.0.1 (host order)
	binary.LittleEndian.PutUint32(data[52:56], 0x0A000002) // daddr 10.0.0.2
	binary.LittleEndian.PutUint16(data[56:58], 54321)      // sport
	binary.LittleEndian.PutUint16(data[58:60], 8443)       // dport
	data[60] = 2                                           // AF_INET

	r, ok := ParseRecord(data)
	if !ok {
		t.Fatal("ParseRecord failed")
	}
	if r.PeerSrcIP != "10.0.0.1" || r.PeerDstIP != "10.0.0.2" {
		t.Errorf("peer IPs = %q -> %q, want 10.0.0.1 -> 10.0.0.2", r.PeerSrcIP, r.PeerDstIP)
	}
	if r.PeerSrcPort != 54321 || r.PeerDstPort != 8443 {
		t.Errorf("peer ports = %d -> %d, want 54321 -> 8443", r.PeerSrcPort, r.PeerDstPort)
	}
}
