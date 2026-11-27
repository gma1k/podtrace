package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/dns"
)

type memoryMap struct {
	rows      map[string][]byte
	failPut   bool
	failRead  error
	deletions int
}

func newMemoryMap() *memoryMap { return &memoryMap{rows: map[string][]byte{}} }

func keyString(key any) string {
	switch k := key.(type) {
	case []byte:
		return string(k)
	}
	panic(fmt.Sprintf("unexpected key %T", key))
}

func (m *memoryMap) Lookup(key, valueOut any) error {
	if m.failRead != nil {
		return m.failRead
	}
	v, ok := m.rows[keyString(key)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	switch out := valueOut.(type) {
	case *[dnsResolvedValueLen]byte:
		copy(out[:], v)
	case *[16]byte:
		copy(out[:], v)
	case *uint32:
		*out = binary.NativeEndian.Uint32(v)
	default:
		panic(fmt.Sprintf("unexpected value %T", valueOut))
	}
	return nil
}

func (m *memoryMap) Update(key, value any, _ ebpf.MapUpdateFlags) error {
	if m.failPut {
		return errors.New("map full")
	}
	switch v := value.(type) {
	case []byte:
		m.rows[keyString(key)] = append([]byte(nil), v...)
	case uint32:
		m.rows[keyString(key)] = binary.NativeEndian.AppendUint32(nil, v)
	default:
		panic(fmt.Sprintf("unexpected value %T", value))
	}
	return nil
}

func (m *memoryMap) Delete(key any) error {
	k := keyString(key)
	if _, ok := m.rows[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.rows, k)
	m.deletions++
	return nil
}

func (m *memoryMap) rowsOf(cgroupID uint64) int {
	n := 0
	for k := range m.rows {
		if binary.NativeEndian.Uint64([]byte(k)[0:8]) == cgroupID {
			n++
		}
	}
	return n
}

type nameCacheMaps struct {
	v4, v6, slots, cursor *memoryMap
	cache                 *dnsNameCache
}

func newNameCacheMaps() nameCacheMaps {
	m := nameCacheMaps{v4: newMemoryMap(), v6: newMemoryMap(), slots: newMemoryMap(), cursor: newMemoryMap()}
	m.cache = &dnsNameCache{v4: m.v4, v6: m.v6, slots: m.slots, cursor: m.cursor}
	return m
}

func ipv4Of(n int) net.IP {
	return net.IPv4(10, byte(n>>16), byte(n>>8), byte(n)).To4()
}

func ipv6Of(n int) net.IP {
	ip := net.ParseIP("2001:db8::").To16()
	binary.BigEndian.PutUint32(ip[12:], uint32(n))
	return ip
}

func (m nameCacheMaps) nameV4(t *testing.T, cgroupID uint64, ip net.IP) (string, bool) {
	t.Helper()
	key := dnsResolvedKeyV4(cgroupID, ip)
	var held [dnsResolvedValueLen]byte
	if m.v4.Lookup(key[:], &held) != nil {
		return "", false
	}
	return string(bytes.TrimRight(held[:dnsResolvedNameLen], "\x00")), true
}

func (m nameCacheMaps) slotV4(t *testing.T, cgroupID uint64, ip net.IP) uint32 {
	t.Helper()
	key := dnsResolvedKeyV4(cgroupID, ip)
	var held [dnsResolvedValueLen]byte
	if err := m.v4.Lookup(key[:], &held); err != nil {
		t.Fatal(err)
	}
	return binary.NativeEndian.Uint32(held[dnsResolvedNameLen:])
}

func TestAPodResolvingManyNamesOnlyReplacesItsOwnOldestNames(t *testing.T) {
	m := newNameCacheMaps()
	const victim, noisy = uint64(100), uint64(200)
	m.cache.rememberV4(victim, ipv4Of(1), "victim.example")
	m.cache.rememberV6(victim, ipv6Of(1), "victim6.example")

	const extra = 37
	for i := 0; i < dnsResolvedCgroupBudget+extra; i++ {
		m.cache.rememberV4(noisy, ipv4Of(i), fmt.Sprintf("n%d.example", i))
		m.cache.rememberV6(noisy, ipv6Of(i), fmt.Sprintf("n%d.example", i))
	}

	if name, ok := m.nameV4(t, victim, ipv4Of(1)); !ok || name != "victim.example" {
		t.Errorf("the victim's name is %q (%v) after another pod resolved %d names", name, ok, dnsResolvedCgroupBudget+extra)
	}
	if got := m.v6.rowsOf(victim); got != 1 {
		t.Errorf("the victim holds %d IPv6 names, want its one", got)
	}
	if got := m.v4.rowsOf(noisy); got != dnsResolvedCgroupBudget {
		t.Errorf("the noisy pod holds %d IPv4 names, want exactly its budget of %d", got, dnsResolvedCgroupBudget)
	}
	if got := m.v6.rowsOf(noisy); got != dnsResolvedCgroupBudget {
		t.Errorf("the noisy pod holds %d IPv6 names, want exactly its budget of %d", got, dnsResolvedCgroupBudget)
	}
	for i := 0; i < extra; i++ {
		if _, ok := m.nameV4(t, noisy, ipv4Of(i)); ok {
			t.Errorf("the noisy pod's oldest name %d survived; the ring must replace it", i)
		}
	}
	if _, ok := m.nameV4(t, noisy, ipv4Of(dnsResolvedCgroupBudget+extra-1)); !ok {
		t.Error("the noisy pod's newest name is missing")
	}
}

func TestTheDecoderUsesItsOwnSlotsSoItNeverRacesTheKernel(t *testing.T) {
	m := newNameCacheMaps()
	m.cache.rememberV4(7, ipv4Of(1), "a.example")
	m.cache.rememberV4(7, ipv4Of(2), "b.example")
	if s := m.slotV4(t, 7, ipv4Of(1)); s != dnsResolvedCgroupBudget {
		t.Errorf("the decoder's first slot is %d, want %d, after the kernel's", s, dnsResolvedCgroupBudget)
	}
	if s := m.slotV4(t, 7, ipv4Of(2)); s != dnsResolvedCgroupBudget+1 {
		t.Errorf("the decoder's second slot is %d, want %d", s, dnsResolvedCgroupBudget+1)
	}
	ck := dnsNameCursorKey(7, dnsNameFamilyV4)
	if binary.NativeEndian.Uint32(ck[12:16]) != dnsNameWriterUser {
		t.Error("the decoder must count on its own cursor, not the kernel's")
	}
}

func TestANameTheKernelAlreadyHoldsIsLeftInItsSlot(t *testing.T) {
	m := newNameCacheMaps()
	key := dnsResolvedKeyV4(9, ipv4Of(5))
	kernel := dnsResolvedValueWithSlot("held.example", 3)
	m.v4.rows[string(key[:])] = kernel[:]

	m.cache.rememberV4(9, ipv4Of(5), "held.example")

	if s := m.slotV4(t, 9, ipv4Of(5)); s != 3 {
		t.Errorf("rewriting the same name moved it to slot %d; the kernel's slot 3 must keep it", s)
	}
	if len(m.slots.rows) != 0 || len(m.cursor.rows) != 0 {
		t.Error("an unchanged name used up a slot")
	}

	m.cache.rememberV4(9, ipv4Of(5), "other.example")
	if name, _ := m.nameV4(t, 9, ipv4Of(5)); name != "other.example" {
		t.Errorf("a new name for the address was not stored, got %q", name)
	}
	if s := m.slotV4(t, 9, ipv4Of(5)); s != dnsResolvedCgroupBudget {
		t.Errorf("the new name sits in slot %d, want the decoder's first slot", s)
	}
}

func TestARefreshedNameOutlivesItsOldSlot(t *testing.T) {
	m := newNameCacheMaps()
	const cg = uint64(11)
	m.cache.rememberV4(cg, ipv4Of(0), "keep.example")
	m.cache.rememberV4(cg, ipv4Of(0), "keep-again.example")
	for i := 1; i < dnsResolvedCgroupBudget; i++ {
		m.cache.rememberV4(cg, ipv4Of(i), "fill.example")
	}
	if name, ok := m.nameV4(t, cg, ipv4Of(0)); !ok || name != "keep-again.example" {
		t.Errorf("a name refreshed one write later is gone (%q, %v) when only its first slot came round", name, ok)
	}
	m.cache.rememberV4(cg, ipv4Of(dnsResolvedCgroupBudget), "push.example")
	if _, ok := m.nameV4(t, cg, ipv4Of(0)); ok {
		t.Error("the refreshed name outlived its own, newer slot")
	}
}

func TestTheRingWrapsAtTheBudget(t *testing.T) {
	m := newNameCacheMaps()
	ck := dnsNameCursorKey(3, dnsNameFamilyV6)
	m.cursor.rows[string(ck[:])] = binary.NativeEndian.AppendUint32(nil, 2*dnsResolvedCgroupBudget+4)
	if got := m.cache.nextSlot(3, dnsNameFamilyV6); got != dnsResolvedCgroupBudget+4 {
		t.Errorf("slot %d, want %d", got, dnsResolvedCgroupBudget+4)
	}
	m.cursor.rows[string(ck[:])] = binary.NativeEndian.AppendUint32(nil, ^uint32(0))
	if got := m.cache.nextSlot(3, dnsNameFamilyV6); got != dnsResolvedCgroupBudget+(^uint32(0))%dnsResolvedCgroupBudget {
		t.Errorf("slot %d at the counter's wrap", got)
	}
	if got := m.cache.nextSlot(3, dnsNameFamilyV6); got != dnsResolvedCgroupBudget {
		t.Errorf("slot %d after the counter wrapped, want the first decoder slot", got)
	}
}

func TestANameIsStillStoredWhenTheRingCannotTrackIt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		breakIt func(nameCacheMaps)
	}{
		{"cursor unreadable", func(m nameCacheMaps) { m.cursor.failRead = errors.New("boom") }},
		{"cursor full", func(m nameCacheMaps) { m.cursor.failPut = true }},
		{"slots full", func(m nameCacheMaps) { m.slots.failPut = true }},
		{"no slot maps", func(m nameCacheMaps) { m.cache.slots = nil; m.cache.cursor = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newNameCacheMaps()
			tc.breakIt(m)
			m.cache.rememberV4(4, ipv4Of(9), "still.example")
			if name, ok := m.nameV4(t, 4, ipv4Of(9)); !ok || name != "still.example" {
				t.Fatalf("name %q (%v); a broken ring must not lose the hostname", name, ok)
			}
			if s := m.slotV4(t, 4, ipv4Of(9)); s != dnsNameNoSlot {
				t.Errorf("an untracked name claims slot %d", s)
			}
		})
	}
}

func TestARecycledSlotWhoseNameIsGoneDeletesNothing(t *testing.T) {
	m := newNameCacheMaps()
	m.cache.rememberV4(5, ipv4Of(1), "gone.example")
	key := dnsResolvedKeyV4(5, ipv4Of(1))
	delete(m.v4.rows, string(key[:]))
	ck := dnsNameCursorKey(5, dnsNameFamilyV4)
	m.cursor.rows[string(ck[:])] = binary.NativeEndian.AppendUint32(nil, dnsResolvedCgroupBudget)
	m.cache.rememberV4(5, ipv4Of(2), "next.example")
	if m.v4.deletions != 0 {
		t.Errorf("%d deletions for a slot whose name the LRU already evicted", m.v4.deletions)
	}
	if _, ok := m.nameV4(t, 5, ipv4Of(2)); !ok {
		t.Error("the new name was not stored")
	}
}

func TestMalformedAddressesAndMissingMapsAreIgnored(t *testing.T) {
	m := newNameCacheMaps()
	m.cache.rememberV4(1, net.ParseIP("2001:db8::1"), "x")
	m.cache.rememberV6(1, net.IPv4(10, 0, 0, 1).To4(), "x")
	if len(m.v4.rows)+len(m.v6.rows) != 0 {
		t.Error("an address of the wrong length was stored")
	}
	var nilCache *dnsNameCache
	nilCache.rememberV4(1, ipv4Of(1), "x")
	nilCache.rememberV6(1, ipv6Of(1), "x")
	partial := &dnsNameCache{}
	partial.rememberV4(1, ipv4Of(1), "x")
	partial.rememberV6(1, ipv6Of(1), "x")
	if newDNSNameCache(nil) != nil {
		t.Error("a cache without a collection")
	}
	if newDNSNameCache(&ebpf.Collection{Maps: map[string]*ebpf.Map{}}) != nil {
		t.Error("a cache without its maps")
	}
}

func TestTheKeysMatchTheKernelLayout(t *testing.T) {
	sk := dnsNameSlotKey(0x0102030405060708, 77, dnsNameFamilyV6)
	if binary.NativeEndian.Uint64(sk[0:8]) != 0x0102030405060708 ||
		binary.NativeEndian.Uint32(sk[8:12]) != 77 ||
		binary.NativeEndian.Uint32(sk[12:16]) != dnsNameFamilyV6 {
		t.Errorf("struct dns_name_slot_key layout: %x", sk)
	}
	v := dnsResolvedValueWithSlot("abc", 9)
	if len(v) != dnsResolvedNameLen+8 || string(v[:3]) != "abc" || v[3] != 0 ||
		binary.NativeEndian.Uint32(v[dnsResolvedNameLen:]) != 9 {
		t.Errorf("struct dns_resolved_name layout: %x", v)
	}
}

func TestPopulateDNSResolvedGoesThroughTheRing(t *testing.T) {
	m := newNameCacheMaps()
	tr := &Tracer{dnsNames: m.cache}
	rec := dns.Record{CgroupID: 42, Msg: dns.Message{QName: "svc.example", Answers: []dns.Answer{
		{Type: dns.TypeA, IP: "10.9.8.7"},
		{Type: dns.TypeAAAA, IP: "2001:db8::7"},
		{Type: dns.TypeCNAME, CNAME: "alias.example"},
		{Type: dns.TypeA, IP: "not-an-ip"},
	}}}
	tr.populateDNSResolved(rec)
	if name, ok := m.nameV4(t, 42, net.ParseIP("10.9.8.7").To4()); !ok || name != "svc.example" {
		t.Errorf("A answer stored as %q (%v)", name, ok)
	}
	if m.v6.rowsOf(42) != 1 || len(m.slots.rows) != 2 {
		t.Errorf("AAAA rows %d, slots %d; both answers must take a slot", m.v6.rowsOf(42), len(m.slots.rows))
	}
	(&Tracer{}).populateDNSResolved(rec)
}
