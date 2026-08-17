package tracer

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestDNSResolvedKeyV4Layout(t *testing.T) {
	const cg = uint64(0xAABBCCDD11223344)
	key := dnsResolvedKeyV4(cg, net.ParseIP("10.1.2.3").To4())

	if len(key) != 16 {
		t.Fatalf("v4 key = %d bytes, want 16 (struct dns_resolved_key)", len(key))
	}
	if got := binary.NativeEndian.Uint64(key[0:8]); got != cg {
		t.Errorf("cgroup_id = %#x, want %#x", got, cg)
	}
	if !bytes.Equal(key[8:12], []byte{10, 1, 2, 3}) {
		t.Errorf("ip bytes = %v, want [10 1 2 3]", key[8:12])
	}
	if !bytes.Equal(key[12:16], []byte{0, 0, 0, 0}) {
		t.Errorf("_pad = %v, want zero", key[12:16])
	}
}

func TestDNSResolvedKeyV6Layout(t *testing.T) {
	const cg = uint64(0x0102030405060708)
	ip6 := net.ParseIP("2001:db8::1").To16()
	key := dnsResolvedKeyV6(cg, ip6)

	if len(key) != 24 {
		t.Fatalf("v6 key = %d bytes, want 24 (struct dns_v6key)", len(key))
	}
	if got := binary.NativeEndian.Uint64(key[0:8]); got != cg {
		t.Errorf("cgroup_id = %#x, want %#x", got, cg)
	}
	if !bytes.Equal(key[8:24], ip6) {
		t.Errorf("addr = %v, want %v", key[8:24], ip6)
	}
}

func TestDNSResolvedKey_DistinctCgroupsDoNotCollide(t *testing.T) {
	ip := net.ParseIP("10.0.0.5").To4()
	a := dnsResolvedKeyV4(1000, ip)
	b := dnsResolvedKeyV4(2000, ip)
	if bytes.Equal(a[:], b[:]) {
		t.Error("same IP under different cgroups must yield different keys (tenant isolation)")
	}
}
