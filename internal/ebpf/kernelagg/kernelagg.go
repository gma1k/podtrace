// Package kernelagg drains the kernel-side metric aggregation map.
//
// The BPF probes fold observations into a per-CPU map instead of shipping one
// ringbuf record per event, which is what turns the metrics plane's cost from
// O(events) into O(series). This package reads that map, sums the per-CPU
// copies, and hands the agent deltas to add into the Prometheus collectors it
// already owns.
package kernelagg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Schema is the Prometheus native-histogram schema the kernel records in.
// Bucket b covers (2^((b-1)/8), 2^(b/8)].
const Schema = 3

// BucketNone marks a row carrying only counters, with no latency observation.
const BucketNone = uint16(0xFFFF)

// MapName, EnabledMapName, ConfigMapName and StatsMapName are the BPF map
// names this package binds to.
const (
	MapName        = "agg_metrics"
	EnabledMapName = "agg_enabled"
	ConfigMapName  = "agg_config"
	StatsMapName   = "agg_stats"
)

// Key mirrors struct agg_key in bpf/agg.h. Field order and padding must match
// the C layout exactly; a mismatch silently misreads every row.
type Key struct {
	CgroupID  uint64
	PeerAddr  [16]byte
	PeerPort  uint16
	EventType uint8
	Variant   uint8
	Bucket    uint16
	Role      uint8
	_         [9]byte
}

// PeerIP returns the row's peer address, or "" when the row has none. An
// IPv4 peer prints in dotted form.
func (k *Key) PeerIP() string {
	if k.PeerAddr == ([16]byte{}) {
		return ""
	}
	return net.IP(k.PeerAddr[:]).String()
}

// V4MappedPeer encodes an IPv4 address given in host byte order the way the
// kernel stores it in Key.PeerAddr.
func V4MappedPeer(ip uint32) [16]byte {
	var addr [16]byte
	addr[10], addr[11] = 0xff, 0xff
	binary.BigEndian.PutUint32(addr[12:], ip)
	return addr
}

// Value mirrors struct agg_value in bpf/agg.h.
type Value struct {
	Count uint64
	SumNS uint64
	Bytes uint64
}

// Row is one drained key with its per-CPU values already summed.
type Row struct {
	Key   Key
	Value Value
}

// Variant unpacks the dimensions the kernel could not derive from event type
// alone.
type Variant struct {
	Transport   uint8
	StatusClass uint8
	IsError     bool
}

// DecodeVariant unpacks the byte packed by AGG_VARIANT in bpf/agg.h.
func DecodeVariant(v uint8) Variant {
	return Variant{
		Transport:   v & 0x7,
		StatusClass: (v >> 3) & 0x7,
		IsError:     v&(1<<6) != 0,
	}
}

// Mode selects what the probes do with an observation.
type Mode uint32

const (
	ModeOff            Mode = 0
	ModeOn             Mode = 1
	ModeBypass         Mode = 2
	ModeBypassExceptL7 Mode = 3
)

func (m Mode) String() string {
	switch m {
	case ModeOn:
		return "on"
	case ModeBypass:
		return "bypass"
	case ModeBypassExceptL7:
		return "bypass-except-l7"
	default:
		return "off"
	}
}

// SetMode tells the probes how to treat observations.
func SetMode(m *ebpf.Map, mode Mode) error {
	if m == nil {
		return errors.New("kernelagg: enabled map is nil")
	}
	key := uint32(0)
	value := uint32(mode)
	if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("kernelagg: set mode: %w", err)
	}
	return nil
}

// Config mirrors struct agg_config in bpf/agg.h.
type Config struct {
	CgroupRowBudget uint32
	Generation      uint32
}

// configMap is the part of *ebpf.Map the budget configuration uses.
type configMap interface {
	Lookup(key, valueOut any) error
	Update(key, value any, flags ebpf.MapUpdateFlags) error
}

// SetCgroupRowBudget sets how many rows one cgroup may create between two
// drains before its new rows are folded onto a peer-less row. Zero turns the
// budget off.
func SetCgroupRowBudget(m configMap, budget uint32) error {
	if m == nil {
		return errors.New("kernelagg: config map is nil")
	}
	key := uint32(0)
	var cfg Config
	if err := m.Lookup(&key, &cfg); err != nil {
		return fmt.Errorf("kernelagg: read config: %w", err)
	}
	cfg.CgroupRowBudget = budget
	if err := m.Update(&key, &cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("kernelagg: set row budget: %w", err)
	}
	return nil
}

// AdvanceGeneration starts a new budget interval: every cgroup's row count
// is treated as zero from here on, without walking the per-cgroup map.
func AdvanceGeneration(m configMap) error {
	if m == nil {
		return errors.New("kernelagg: config map is nil")
	}
	key := uint32(0)
	var cfg Config
	if err := m.Lookup(&key, &cfg); err != nil {
		return fmt.Errorf("kernelagg: read config: %w", err)
	}
	cfg.Generation++
	if err := m.Update(&key, &cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("kernelagg: advance generation: %w", err)
	}
	return nil
}

// Stats are the kernel's running counters for the metrics map, mirroring
// the AGG_STAT_* slots of agg_stats in bpf/agg.h.
type Stats struct {
	RowsCreated   uint64
	PeerCollapsed uint64
}

const (
	statRowsCreated   = uint32(0)
	statPeerCollapsed = uint32(1)
)

// statsMap is the part of *ebpf.Map reading the counters uses.
type statsMap interface {
	Lookup(key, valueOut any) error
}

// ReadStats sums the per-CPU copies of the kernel's metrics-map counters.
func ReadStats(m statsMap) (Stats, error) {
	if m == nil {
		return Stats{}, errors.New("kernelagg: stats map is nil")
	}
	read := func(slot uint32) (uint64, error) {
		var perCPU []uint64
		if err := m.Lookup(&slot, &perCPU); err != nil {
			return 0, fmt.Errorf("kernelagg: read stat %d: %w", slot, err)
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		return total, nil
	}
	created, err := read(statRowsCreated)
	if err != nil {
		return Stats{}, err
	}
	collapsed, err := read(statPeerCollapsed)
	if err != nil {
		return Stats{}, err
	}
	return Stats{RowsCreated: created, PeerCollapsed: collapsed}, nil
}

// Pressure is what the metrics map lost or folded since the probes loaded.
type Pressure struct {
	RowsEvicted   uint64
	PeerCollapsed uint64
}

// PressureTracker turns the kernel's row-creation counter and the rows each
// drain takes into a running count of rows the LRU evicted before a drain
// reached them.
type PressureTracker struct {
	taken    uint64
	pressure Pressure
}

// Observe folds one drain into the tracker: the stats read just before it,
// and how many rows it took.
func (p *PressureTracker) Observe(before Stats, taken int) Pressure {
	if taken > 0 {
		p.taken += uint64(taken)
	}
	if before.RowsCreated > p.taken {
		if lost := before.RowsCreated - p.taken; lost > p.pressure.RowsEvicted {
			p.pressure.RowsEvicted = lost
		}
	}
	if before.PeerCollapsed > p.pressure.PeerCollapsed {
		p.pressure.PeerCollapsed = before.PeerCollapsed
	}
	return p.pressure
}

// Pressure returns the totals folded in so far.
func (p *PressureTracker) Pressure() Pressure {
	return p.pressure
}

// Drain reads every row and removes it, returning the summed deltas.
//
// Each row is read and removed in one step. Reading every row first and
// deleting them all afterwards loses whatever the probes add to a row in
// between, an undercount that grows with the number of series.
func Drain(m *ebpf.Map) ([]Row, error) {
	rows, _, err := DrainCounted(m)
	return rows, err
}

// DrainCounted is Drain that also reports how many rows it removed from the
// map, including rows whose delta was zero.
func DrainCounted(m *ebpf.Map) ([]Row, int, error) {
	if m == nil {
		return nil, 0, errors.New("kernelagg: metrics map is nil")
	}
	iter := m.Iterate()
	t := &mapTaker{m: m}
	return drainRowsCounted(iter.Next, iter.Err, t.take)
}

// rowMap is the part of *ebpf.Map a drain uses.
type rowMap interface {
	LookupAndDelete(key, valueOut any) error
	Lookup(key, valueOut any) error
	Delete(key any) error
}

// mapTaker removes one row at a time, atomically where the kernel can.
type mapTaker struct {
	m        rowMap
	separate bool
}

func (t *mapTaker) take(k *Key) (Value, error) {
	var perCPU []Value
	if !t.separate {
		err := t.m.LookupAndDelete(k, &perCPU)
		if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
			return SumPerCPU(perCPU), nil
		}
		if !errors.Is(err, ebpf.ErrNotSupported) && !errors.Is(err, unix.EINVAL) {
			return Value{}, err
		}
		t.separate = true
	}
	if err := t.m.Lookup(k, &perCPU); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Value{}, nil
		}
		return Value{}, err
	}
	if err := t.m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return Value{}, err
	}
	return SumPerCPU(perCPU), nil
}

// drainRows holds the drain logic, separated from the map I/O so it can be
// exercised without a BPF map, creating one needs privileges a unit test
// does not have.
func drainRows(
	next func(key, value any) bool,
	iterErr func() error,
	take func(*Key) (Value, error),
) ([]Row, error) {
	rows, _, err := drainRowsCounted(next, iterErr, take)
	return rows, err
}

// drainRowsCounted collects the keys first, then takes each: the read and
// the removal of a row happen together.
func drainRowsCounted(
	next func(key, value any) bool,
	iterErr func() error,
	take func(*Key) (Value, error),
) ([]Row, int, error) {
	var (
		key    Key
		perCPU []Value
		keys   []Key
		rows   []Row
	)

	seen := make(map[Key]struct{})
	for next(&key, &perCPU) {
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	if err := iterErr(); err != nil && !errors.Is(err, ebpf.ErrIterationAborted) {
		return nil, 0, fmt.Errorf("kernelagg: iterate: %w", err)
	}

	var failed []error
	taken := 0
	for i := range keys {
		total, err := take(&keys[i])
		if err != nil {
			failed = append(failed, err)
			continue
		}
		taken++
		if total.Count == 0 && total.Bytes == 0 {
			continue
		}
		rows = append(rows, Row{Key: keys[i], Value: total})
	}
	if len(failed) > 0 {
		return rows, taken, fmt.Errorf("kernelagg: take failed for %d of %d rows: %w", len(failed), len(keys), errors.Join(failed...))
	}
	return rows, taken, nil
}

// SumPerCPU folds the per-CPU copies of one row into a single delta.
func SumPerCPU(vals []Value) Value {
	var total Value
	for _, v := range vals {
		total.Count += v.Count
		total.SumNS += v.SumNS
		total.Bytes += v.Bytes
	}
	return total
}

// BucketUpperBound returns the inclusive upper bound, in seconds, of a
// schema-3 bucket.
func BucketUpperBound(bucket uint16) float64 {
	return math.Exp2(float64(bucket) / float64(uint(1)<<Schema))
}

// schemaBounds are the normalized upper bounds of the schema-3 sub-buckets
// within [0.5, 1), matching what client_golang searches when it places a
// value.
var schemaBounds = func() []float64 {
	steps := 1 << Schema
	out := make([]float64, steps)
	for k := 1; k <= steps; k++ {
		out[k-1] = 0.5 * math.Exp2(float64(k)/float64(steps))
	}
	return out
}()

// BucketIndex returns the kernel's bucket for a nanosecond duration,
// mirroring agg_bucket(agg_scale(ns)) in bpf/agg.h.
func BucketIndex(ns uint64) uint16 {
	v := ScaledUnits(ns)
	if v == 0 {
		return 0
	}
	frac, exp := math.Frexp(float64(v))
	return clampBucket(sort.SearchFloat64s(schemaBounds, frac) + (exp-1)*(1<<Schema))
}

const scaleUnitLog2 = 30

// ScaledUnits converts nanoseconds to 2^-30-second units, exactly
// floor(ns * 2^30 / 10^9), in the same integer steps as agg_scale() in
// bpf/agg.h so both sides bucket identically.
func ScaledUnits(ns uint64) uint64 {
	const (
		correction  = 73741824 // 2^30 - 10^9
		nsPerSecond = 1000000000
	)
	whole := ns / nsPerSecond
	rest := ns - whole*nsPerSecond
	return ns + whole*correction + rest*correction/nsPerSecond
}

const nativeIndexOffset = scaleUnitLog2*(1<<Schema) - 1

// NativeIndex returns the Prometheus native-histogram bucket, in seconds, that
// a kernel bucket corresponds to.
func NativeIndex(bucket uint16) int {
	return int(bucket) - nativeIndexOffset
}

// clampBucket narrows a computed index to the width the kernel key uses.
func clampBucket(index int) uint16 {
	if index < 0 {
		return 0
	}
	if index > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(index)
}
