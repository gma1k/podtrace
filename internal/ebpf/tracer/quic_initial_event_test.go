package tracer

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/quicinitial"
	"github.com/gma1k/podtrace/internal/events"
)

func quicVarint(v int) []byte {
	if v < 64 {
		return []byte{byte(v)}
	}
	return []byte{0x40 | byte(v>>8), byte(v)}
}

func quicClientHello(host string, alpn []string) []byte {
	sni := []byte{0, 0, 0x00, byte(len(host) >> 8), byte(len(host))}
	sni = append(sni, host...)
	binary.BigEndian.PutUint16(sni, uint16(len(sni)-2))
	ext := []byte{0x00, 0x00, byte(len(sni) >> 8), byte(len(sni))}
	ext = append(ext, sni...)
	if len(alpn) > 0 {
		var list []byte
		for _, p := range alpn {
			list = append(list, byte(len(p)))
			list = append(list, p...)
		}
		body := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
		ext = append(ext, 0x00, 0x10, byte(len(body)>>8), byte(len(body)))
		ext = append(ext, body...)
	}
	body := make([]byte, 2+32)
	body = append(body, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	return append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func quicSealedInitial(t *testing.T, dcid, hello []byte) []byte {
	t.Helper()
	keys := quicinitial.DeriveClientInitialKeys(dcid)
	payload := append([]byte{0x06, 0x00}, quicVarint(len(hello))...)
	payload = append(payload, hello...)
	hdr := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, byte(len(dcid))}
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00, 0x00)
	hdr = append(hdr, quicVarint(1+len(payload)+16)...)
	pnOffset := len(hdr)
	hdr = append(hdr, 0x00)

	block, err := aes.NewCipher(keys.Key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	pkt := append(append([]byte{}, hdr...), gcm.Seal(nil, keys.IV, payload, hdr)...)
	hp, err := aes.NewCipher(keys.HP)
	if err != nil {
		t.Fatal(err)
	}
	mask := make([]byte, 16)
	hp.Encrypt(mask, pkt[pnOffset+4:pnOffset+20])
	pkt[0] ^= mask[0] & 0x0f
	pkt[pnOffset] ^= mask[1]
	return pkt
}

type quicRecord struct {
	stamp  uint64
	cgroup uint64
	pid    uint32
	v6     bool
	addr   net.IP
	dport  uint16
	lport  uint16
	comm   string
	pkt    []byte
	length int
}

func (r quicRecord) bytes() []byte {
	data := make([]byte, quicInitialRecordHeader)
	binary.LittleEndian.PutUint64(data[0:], r.stamp)
	binary.LittleEndian.PutUint64(data[8:], r.cgroup)
	binary.LittleEndian.PutUint32(data[16:], r.pid)
	data[20] = 2
	if r.v6 {
		data[20] = 10
		copy(data[24:40], r.addr.To16())
	} else {
		copy(data[24:28], r.addr.To4())
	}
	binary.LittleEndian.PutUint16(data[22:], r.dport)
	length := r.length
	if length == 0 {
		length = len(r.pkt)
	}
	binary.LittleEndian.PutUint16(data[40:], uint16(length))
	binary.LittleEndian.PutUint16(data[42:], r.lport)
	copy(data[44:60], r.comm)
	return append(data, r.pkt...)
}

func TestQUICInitialEventReportsTheServerNameOnce(t *testing.T) {
	now := time.Now()
	flows := map[quicFlowKey]*quicFlowState{}
	rec := quicRecord{
		stamp: 1_000, cgroup: 77, pid: 4321, addr: net.IPv4(10, 0, 0, 9), dport: 443, lport: 50001,
		comm: "curl", pkt: quicSealedInitial(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, quicClientHello("api.example", []string{"h3", "h3-29"})),
	}
	ev := quicInitialEvent(flows, rec.bytes(), now)
	if ev == nil {
		t.Fatal("a complete ClientHello must produce a connection event")
	}
	if ev.Type != events.EventHTTP3 || ev.Details != "sni: api.example alpn: h3,h3-29" {
		t.Fatalf("event = %v %q", ev.Type, ev.Details)
	}
	if ev.Target != "10.0.0.9:443" || ev.PeerDstIP != "10.0.0.9" || ev.PeerDstPort != 443 {
		t.Fatalf("peer = %q %q %d", ev.Target, ev.PeerDstIP, ev.PeerDstPort)
	}
	if ev.PID != 4321 || ev.CgroupID != 77 || ev.ProcessName != "curl" || ev.Timestamp != 1_000 {
		t.Fatalf("identity = pid %d cgroup %d comm %q ts %d", ev.PID, ev.CgroupID, ev.ProcessName, ev.Timestamp)
	}
	rec.stamp = 2_000
	if quicInitialEvent(flows, rec.bytes(), now) != nil {
		t.Fatal("a retransmitted Initial of a reported connection must not be reported again")
	}
}

func TestQUICInitialEventWithoutALPNNamesOnlyTheServer(t *testing.T) {
	rec := quicRecord{
		addr: net.IPv4(10, 0, 0, 9), dport: 443, lport: 50001,
		pkt: quicSealedInitial(t, []byte{8, 7, 6, 5}, quicClientHello("plain.example", nil)),
	}
	ev := quicInitialEvent(map[quicFlowKey]*quicFlowState{}, rec.bytes(), time.Now())
	if ev == nil || ev.Details != "sni: plain.example" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestQUICInitialEventGivesUpAfterThePacketBudget(t *testing.T) {
	now := time.Now()
	flows := map[quicFlowKey]*quicFlowState{}
	rec := quicRecord{
		v6: true, addr: net.ParseIP("2001:db8::7"), dport: 8443, lport: 40000,
		pkt: []byte{0xc0, 1, 2, 3}, length: 400,
	}
	for i := 1; i < quicInitialMaxPackets; i++ {
		if quicInitialEvent(flows, rec.bytes(), now) != nil {
			t.Fatalf("packet %d of an unreadable flow must wait for the rest of the budget", i)
		}
	}
	ev := quicInitialEvent(flows, rec.bytes(), now)
	if ev == nil || ev.Details != "HTTP/3 (QUIC)" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Target != "2001:db8::7:8443" {
		t.Fatalf("target = %q", ev.Target)
	}
}

func TestQUICInitialEventSeparatesConnectionsByLocalPort(t *testing.T) {
	now := time.Now()
	flows := map[quicFlowKey]*quicFlowState{}
	hello := quicClientHello("api.example", nil)
	for i, lport := range []uint16{50001, 50002} {
		rec := quicRecord{
			addr: net.IPv4(10, 0, 0, 9), dport: 443, lport: lport,
			pkt: quicSealedInitial(t, []byte{byte(i), 1, 2, 3}, hello),
		}
		if quicInitialEvent(flows, rec.bytes(), now) == nil {
			t.Fatalf("connection from local port %d was not reported", lport)
		}
	}
}

func TestQUICInitialEventIgnoresATruncatedRecord(t *testing.T) {
	flows := map[quicFlowKey]*quicFlowState{}
	if quicInitialEvent(flows, make([]byte, quicInitialRecordHeader), time.Now()) != nil || len(flows) != 0 {
		t.Fatal("a record without packet bytes must be dropped before it creates a flow")
	}
}

func TestQUICInitialReaderDispatchesEachConnectionUntilClosed(t *testing.T) {
	tr := newDispatchTestTracer()
	hello := quicClientHello("api.example", []string{"h3"})
	first := quicRecord{
		addr: net.IPv4(10, 0, 0, 9), dport: 443, lport: 50001, comm: "curl",
		pkt: quicSealedInitial(t, []byte{1, 1, 1, 1}, hello),
	}
	second := first
	second.lport = 50002
	second.pkt = quicSealedInitial(t, []byte{2, 2, 2, 2}, hello)
	reader := &fakeRecordReader{records: [][]byte{nil, first.bytes(), first.bytes(), make([]byte, 8), second.bytes()}}
	tr.quicReader = reader

	var collected, filtered, parsed atomic.Int64
	var filteringDisabled atomic.Bool
	filteringDisabled.Store(true)
	ch := make(chan *events.Event, 16)
	tr.runQUICInitialReader(context.Background(), ch, nil, &eventCounters{
		collected: &collected, filtered: &filtered, parsed: &parsed, filteringDisabled: &filteringDisabled,
	})

	if reader.reads != 6 {
		t.Fatalf("reads = %d, want the loop to continue past errors until closed", reader.reads)
	}
	close(ch)
	var got []string
	for ev := range ch {
		got = append(got, ev.Details)
	}
	if len(got) != 2 || got[0] != "sni: api.example alpn: h3" || got[1] != got[0] {
		t.Fatalf("dispatched %q, want one event per connection", got)
	}
}

func TestQUICInitialReaderStopsWhenCancelled(t *testing.T) {
	tr := newDispatchTestTracer()
	reader := &fakeRecordReader{records: [][]byte{make([]byte, 8)}}
	tr.quicReader = reader
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr.runQUICInitialReader(ctx, make(chan *events.Event, 1), nil, &eventCounters{})
	if reader.reads != 0 {
		t.Fatalf("reads = %d, a cancelled reader must not read", reader.reads)
	}
}
