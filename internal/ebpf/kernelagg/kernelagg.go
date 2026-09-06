// Package kernelagg drains the kernel-side metric aggregation map.
//
// The BPF probes fold observations into a per-CPU map instead of shipping one
// ringbuf record per event, which is what turns the metrics plane's cost from
// O(events) into O(series). This package reads that map, sums the per-CPU
// copies, and hands the agent deltas to add into the Prometheus collectors it
// already owns.
package kernelagg

import (
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/cilium/ebpf"
)

// Schema is the Prometheus native-histogram schema the kernel records in.
// Bucket b covers (2^((b-1)/8), 2^(b/8)].
const Schema = 3

// BucketNone marks a row carrying only counters, with no latency observation.
const BucketNone = uint16(0xFFFF)

// MapName and EnabledMapName are the BPF map names this package binds to.
const (
	MapName        = "agg_metrics"
	EnabledMapName = "agg_enabled"
)

// Key mirrors struct agg_key in bpf/agg.h. Field order and padding must match
// the C layout exactly; a mismatch silently misreads every row.
type Key struct {
	CgroupID  uint64
	PeerIP    uint32
	PeerPort  uint16
	EventType uint8
	Variant   uint8
	Bucket    uint16
	_         [6]byte
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
	ModeOff    Mode = 0
	ModeOn     Mode = 1
	ModeBypass Mode = 2
)

func (m Mode) String() string {
	switch m {
	case ModeOn:
		return "on"
	case ModeBypass:
		return "bypass"
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

// Drain reads every row and removes it, returning the summed deltas.
func Drain(m *ebpf.Map) ([]Row, error) {
	if m == nil {
		return nil, errors.New("kernelagg: metrics map is nil")
	}
	iter := m.Iterate()
	return drainRows(iter.Next, iter.Err, func(k *Key) error { return m.Delete(k) })
}

// drainRows holds the drain logic, separated from the map I/O so it can be
// exercised without a BPF map, creating one needs privileges a unit test
// does not have.
func drainRows(
	next func(key, value any) bool,
	iterErr func() error,
	del func(*Key) error,
) ([]Row, error) {
	var (
		key     Key
		perCPU  []Value
		rows    []Row
		drained []Key
	)

	for next(&key, &perCPU) {
		total := SumPerCPU(perCPU)
		drained = append(drained, key)
		if total.Count == 0 && total.Bytes == 0 {
			continue
		}
		rows = append(rows, Row{Key: key, Value: total})
	}
	if err := iterErr(); err != nil {
		return nil, fmt.Errorf("kernelagg: iterate: %w", err)
	}

	for i := range drained {
		if err := del(&drained[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return rows, fmt.Errorf("kernelagg: delete: %w", err)
		}
	}
	return rows, nil
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

// BucketIndex returns the schema-3 bucket a nanosecond duration falls in,
// mirroring agg_bucket() in bpf/agg.h.
func BucketIndex(ns uint64) uint16 {
	if ns == 0 {
		return 0
	}
	frac, exp := math.Frexp(float64(ns))
	return clampBucket(sort.SearchFloat64s(schemaBounds, frac) + (exp-1)*(1<<Schema))
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
