package tracer

import (
	"testing"
	"unsafe"
)

// The Go structs must match the C layout in bpf/maps.h exactly, or reading
// dns_inflight in the timeout sweep yields garbage.
func TestDNSStructLayout(t *testing.T) {
	if got := unsafe.Sizeof(dnsFlowKey{}); got != 16 {
		t.Errorf("dnsFlowKey size = %d, want 16 (u64 cgroup_id + u32 txid + u32 pad)", got)
	}
	if got := unsafe.Sizeof(dnsQueryState{}); got != 184 {
		t.Errorf("dnsQueryState size = %d, want 184", got)
	}
}

func TestMonotonicNowNS(t *testing.T) {
	a := monotonicNowNS()
	if a == 0 {
		t.Fatal("monotonicNowNS returned 0")
	}
	b := monotonicNowNS()
	if b < a {
		t.Errorf("monotonic clock went backwards: %d < %d", b, a)
	}
}
