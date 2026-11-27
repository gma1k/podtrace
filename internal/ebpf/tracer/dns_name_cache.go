package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"

	"github.com/cilium/ebpf"
)

// These mirror bpf/maps.h and bpf/common.h.
const (
	dnsResolvedCgroupBudget = 8192
	dnsNameNoSlot           = ^uint32(0)
	dnsNameWriterUser       = 1
	dnsNameFamilyV4         = 2
	dnsNameFamilyV6         = 10
	dnsResolvedValueLen     = dnsResolvedNameLen + 8
)

// dnsNameMap is the part of a BPF map the hostname cache uses.
type dnsNameMap interface {
	Lookup(key, valueOut any) error
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
}

// dnsNameCache writes the hostnames the payload decoder recovers into the
// kernel's per-cgroup hostname cache (dns_resolved, dns_resolved6), keeping
// the same rule the kernel keeps: each cgroup owns a ring of slots, and a
// new name of that cgroup replaces the oldest name of that same cgroup, so
// a pod that resolves many names can never push out another pod's names.
// The decoder uses its own ring (slots dnsResolvedCgroupBudget and up), so
// it never races the kernel for a slot.
type dnsNameCache struct {
	v4, v6 dnsNameMap
	slots  dnsNameMap
	cursor dnsNameMap
}

func newDNSNameCache(coll *ebpf.Collection) *dnsNameCache {
	if coll == nil {
		return nil
	}
	c := &dnsNameCache{}
	if m := coll.Maps["dns_resolved"]; m != nil {
		c.v4 = m
	}
	if m := coll.Maps["dns_resolved6"]; m != nil {
		c.v6 = m
	}
	if m := coll.Maps["dns_name_slots"]; m != nil {
		c.slots = m
	}
	if m := coll.Maps["dns_name_cursor"]; m != nil {
		c.cursor = m
	}
	if c.v4 == nil && c.v6 == nil {
		return nil
	}
	return c
}

func dnsResolvedValueWithSlot(name string, slot uint32) [dnsResolvedValueLen]byte {
	var buf [dnsResolvedValueLen]byte
	n := dnsResolvedValue(name)
	copy(buf[:dnsResolvedNameLen], n[:])
	binary.NativeEndian.PutUint32(buf[dnsResolvedNameLen:], slot)
	return buf
}

func dnsNameSlotKey(cgroupID uint64, slot, family uint32) [16]byte {
	var key [16]byte
	binary.NativeEndian.PutUint64(key[0:8], cgroupID)
	binary.NativeEndian.PutUint32(key[8:12], slot)
	binary.NativeEndian.PutUint32(key[12:16], family)
	return key
}

func dnsNameCursorKey(cgroupID uint64, family uint32) [16]byte {
	var key [16]byte
	binary.NativeEndian.PutUint64(key[0:8], cgroupID)
	binary.NativeEndian.PutUint32(key[8:12], family)
	binary.NativeEndian.PutUint32(key[12:16], dnsNameWriterUser)
	return key
}

// rememberV4 stores name for an A answer of cgroupID.
func (c *dnsNameCache) rememberV4(cgroupID uint64, ip4 net.IP, name string) {
	if c == nil || c.v4 == nil || len(ip4) != net.IPv4len {
		return
	}
	key := dnsResolvedKeyV4(cgroupID, ip4)
	var addr [16]byte
	copy(addr[:], ip4)
	c.remember(c.v4, key[:], cgroupID, dnsNameFamilyV4, addr, name)
}

// rememberV6 stores name for an AAAA answer of cgroupID.
func (c *dnsNameCache) rememberV6(cgroupID uint64, ip6 net.IP, name string) {
	if c == nil || c.v6 == nil || len(ip6) != net.IPv6len {
		return
	}
	key := dnsResolvedKeyV6(cgroupID, ip6)
	var addr [16]byte
	copy(addr[:], ip6)
	c.remember(c.v6, key[:], cgroupID, dnsNameFamilyV6, addr, name)
}

func (c *dnsNameCache) remember(store dnsNameMap, key []byte, cgroupID uint64, family uint32, addr [16]byte, name string) {
	want := dnsResolvedValue(name)
	var held [dnsResolvedValueLen]byte
	if store.Lookup(key, &held) == nil && bytes.Equal(held[:dnsResolvedNameLen], want[:]) {
		return
	}
	slot := c.nextSlot(cgroupID, family)
	if slot != dnsNameNoSlot {
		c.recycle(store, cgroupID, family, slot)
		sk := dnsNameSlotKey(cgroupID, slot, family)
		if err := c.slots.Update(sk[:], addr[:], ebpf.UpdateAny); err != nil {
			slot = dnsNameNoSlot
		}
	}
	value := dnsResolvedValueWithSlot(name, slot)
	_ = store.Update(key, value[:], ebpf.UpdateAny)
}

// nextSlot hands out the decoder's next slot of cgroupID's ring. Only the
// payload reader goroutine writes here, so a read and a write are enough.
func (c *dnsNameCache) nextSlot(cgroupID uint64, family uint32) uint32 {
	if c.slots == nil || c.cursor == nil {
		return dnsNameNoSlot
	}
	ck := dnsNameCursorKey(cgroupID, family)
	var next uint32
	if err := c.cursor.Lookup(ck[:], &next); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return dnsNameNoSlot
	}
	if err := c.cursor.Update(ck[:], next+1, ebpf.UpdateAny); err != nil {
		return dnsNameNoSlot
	}
	return dnsResolvedCgroupBudget + next%dnsResolvedCgroupBudget
}

// recycle drops the name that last used slot, unless that name has been
// written again since and so now belongs to a newer slot.
func (c *dnsNameCache) recycle(store dnsNameMap, cgroupID uint64, family, slot uint32) {
	sk := dnsNameSlotKey(cgroupID, slot, family)
	var old [16]byte
	if c.slots.Lookup(sk[:], &old) != nil {
		return
	}
	var key []byte
	if family == dnsNameFamilyV4 {
		k := dnsResolvedKeyV4(cgroupID, net.IP(old[:net.IPv4len]))
		key = k[:]
	} else {
		k := dnsResolvedKeyV6(cgroupID, net.IP(old[:]))
		key = k[:]
	}
	var held [dnsResolvedValueLen]byte
	if store.Lookup(key, &held) != nil {
		return
	}
	if binary.NativeEndian.Uint32(held[dnsResolvedNameLen:]) == slot {
		_ = store.Delete(key)
	}
}
