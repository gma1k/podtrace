// Package oncpu runs the timer-driven on-CPU sampler and drains what it
// counted.
//
// A cpu-clock perf event on every CPU fires perf_event_oncpu_sample at a fixed
// rate. The program records the running task's user stack in a STACK_TRACE map
// and bumps a count keyed by (cgroup, pid, stack, request), so userspace reads
// one row per distinct stack rather than one record per sample.
package oncpu

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

const SampleHz = 99

// Map and program names this package binds to, as declared in bpf/maps.h and
// bpf/oncpu.c.
const (
	ProgramName         = "perf_event_oncpu_sample"
	TaskRegsProgramName = "perf_event_oncpu_sample_task_regs"
	CountsMapName       = "oncpu_counts"
	StacksMapName       = "oncpu_stacks"
	EnabledMapName      = "oncpu_enabled"
	RequestsMapName     = "oncpu_requests_done"
	LostMapName         = "oncpu_lost"
)

// Lost-sample reasons, the indexes of the oncpu_lost array.
const (
	LostStack uint32 = iota
	LostFull
	lostReasons
)

// LostReason names a lost-sample index for a metric label.
func LostReason(i uint32) string {
	switch i {
	case LostStack:
		return "stack_unavailable"
	case LostFull:
		return "count_map_full"
	default:
		return "unknown"
	}
}

// Key mirrors struct oncpu_key in bpf/maps.h.
type Key struct {
	CgroupID      uint64
	CorrelationID uint64
	PID           uint32
	// StackID is the id bpf_get_stackid returned. The sampler records a
	// sample only when that call succeeds, so it is never negative.
	StackID uint32
}

// Done mirrors struct oncpu_request_done in bpf/maps.h.
type Done struct {
	LatencyNS uint64
	CgroupID  uint64
}

// Sample is one drained count: how many times a process was seen running one
// stack, and the request it was serving if the sampler knew of one.
type Sample struct {
	CgroupID      uint64
	PID           uint32
	CorrelationID uint64
	Stack         []uint64
	Count         uint64
}

// Completion is a served request the attribution hooks saw finish.
type Completion struct {
	CorrelationID uint64
	CgroupID      uint64
	LatencyNS     uint64
}

// Drained is one drain's worth of samples, completions and losses.
type Drained struct {
	Samples     []Sample
	Completions []Completion
	// Lost counts samples the kernel could not record, by reason index.
	Lost [lostReasons]uint64
	// Unresolved counts samples whose stack was gone by the time it was read.
	Unresolved uint64
}

// LostTotals is the running total of each lost-sample counter as of the last
// drain.
type LostTotals [lostReasons]uint64

// Maps is the set of maps a drain reads.
type Maps struct {
	Counts   *ebpf.Map
	Stacks   *ebpf.Map
	Requests *ebpf.Map
	Lost     *ebpf.Map
}

// MapsFrom picks the sampler's maps out of a loaded collection.
func MapsFrom(maps map[string]*ebpf.Map) (Maps, error) {
	m := Maps{
		Counts:   maps[CountsMapName],
		Stacks:   maps[StacksMapName],
		Requests: maps[RequestsMapName],
		Lost:     maps[LostMapName],
	}
	if m.Counts == nil || m.Stacks == nil || m.Requests == nil || m.Lost == nil {
		return Maps{}, errors.New("oncpu: the BPF object has no on-CPU sampler maps")
	}
	return m, nil
}

// The consumers that need requests tracked, as bits of the enabled map's
// value. The request hooks run while any bit is set; each consumer only reads
// its own.
const (
	FlagSampler uint32 = 1 << iota
	FlagRequests
)

// SetFlags writes which consumers are on. Zero switches the request hooks
// off.
func SetFlags(m *ebpf.Map, flags uint32) error {
	if m == nil {
		return errors.New("oncpu: enabled map is nil")
	}
	key := uint32(0)
	if err := m.Update(&key, &flags, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("oncpu: set flags: %w", err)
	}
	return nil
}

// Drain reads and clears everything the sampler recorded since the last
// drain. seen carries the lost-sample totals between drains of the same maps;
// a nil seen reports the counters' whole totals.
func Drain(m Maps, seen *LostTotals) (Drained, error) {
	counts := m.Counts.Iterate()
	requests := m.Requests.Iterate()
	return drain(drainIO{
		nextCount: counts.Next,
		countErr:  counts.Err,
		takeCount: takeCountFrom(m.Counts),
		lookupStack: func(id uint32, out *[stackDepth]uint64) error {
			return m.Stacks.Lookup(id, out)
		},
		deleteStack:   func(id uint32) error { return m.Stacks.Delete(id) },
		liveCounts:    func() []countRow { return liveCounts(m.Counts.Iterate()) },
		nextRequest:   requests.Next,
		requestErr:    requests.Err,
		deleteRequest: func(id *uint64) error { return m.Requests.Delete(id) },
		readLost: func(reason uint32, out *[]uint64) error {
			return m.Lost.Lookup(reason, out)
		},
	}, seen)
}

// stackDepth is MAX_STACK_DEPTH in bpf/common.h.
const stackDepth = 64

// drainIO is the map I/O a drain performs, separated so the drain logic runs
// in a unit test without the privileges creating a BPF map needs.
type drainIO struct {
	nextCount     func(key, value any) bool
	countErr      func() error
	takeCount     func(key *Key, count *uint64) error
	lookupStack   func(uint32, *[stackDepth]uint64) error
	deleteStack   func(uint32) error
	liveCounts    func() []countRow
	nextRequest   func(key, value any) bool
	requestErr    func() error
	deleteRequest func(*uint64) error
	readLost      func(uint32, *[]uint64) error
}

// countRow is one count row as an iteration saw it.
type countRow struct {
	key   Key
	count uint64
}

func outpaced(err error) bool {
	return errors.Is(err, ebpf.ErrIterationAborted)
}

func drain(io drainIO, seen *LostTotals) (Drained, error) {
	var (
		out   Drained
		key   Key
		count uint64
		keys  []Key
		rows  []uint64
	)
	for io.nextCount(&key, &count) {
		keys = append(keys, key)
		rows = append(rows, count)
	}
	if err := io.countErr(); err != nil && !outpaced(err) {
		return Drained{}, fmt.Errorf("oncpu: iterate counts: %w", err)
	}
	for i := range keys {
		if err := io.takeCount(&keys[i], &rows[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return Drained{}, fmt.Errorf("oncpu: delete count: %w", err)
		}
	}

	stacks := map[uint32][]uint64{}
	for i, k := range keys {
		stack, seen := stacks[k.StackID]
		if !seen {
			var ips [stackDepth]uint64
			if err := io.lookupStack(k.StackID, &ips); err == nil {
				stack = trimStack(ips[:])
			}
			stacks[k.StackID] = stack
		}
		if len(stack) == 0 {
			out.Unresolved += rows[i]
			continue
		}
		out.Samples = append(out.Samples, Sample{
			CgroupID:      k.CgroupID,
			PID:           k.PID,
			CorrelationID: k.CorrelationID,
			Stack:         stack,
			Count:         rows[i],
		})
	}
	live := map[uint32]struct{}{}
	for _, r := range io.liveCounts() {
		live[r.key.StackID] = struct{}{}
	}
	deleted := map[uint32]struct{}{}
	for id := range stacks {
		if _, referenced := live[id]; referenced {
			continue
		}
		if err := io.deleteStack(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return Drained{}, fmt.Errorf("oncpu: delete stack: %w", err)
		}
		deleted[id] = struct{}{}
	}
	orphaned, err := takeOrphanedCounts(io, deleted)
	if err != nil {
		return Drained{}, err
	}
	out.Unresolved += orphaned

	var (
		id   uint64
		done Done
		ids  []uint64
	)
	for io.nextRequest(&id, &done) {
		ids = append(ids, id)
		out.Completions = append(out.Completions, Completion{
			CorrelationID: id,
			CgroupID:      done.CgroupID,
			LatencyNS:     done.LatencyNS,
		})
	}
	if err := io.requestErr(); err != nil && !outpaced(err) {
		return Drained{}, fmt.Errorf("oncpu: iterate requests: %w", err)
	}
	for i := range ids {
		if err := io.deleteRequest(&ids[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return Drained{}, fmt.Errorf("oncpu: delete request: %w", err)
		}
	}

	if seen == nil {
		seen = &LostTotals{}
	}
	for reason := uint32(0); reason < lostReasons; reason++ {
		var perCPU []uint64
		if err := io.readLost(reason, &perCPU); err != nil {
			return Drained{}, fmt.Errorf("oncpu: read lost: %w", err)
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		out.Lost[reason] = lostSince(seen[reason], total)
		seen[reason] = total
	}
	return out, nil
}

// lostSince is how much a never-reset counter grew since the last drain. A
// total below the last one means the maps were recreated, and the whole
// total is new.
func lostSince(last, total uint64) uint64 {
	if total < last {
		return total
	}
	return total - last
}

// takeOrphanedCounts removes the count rows a sample recorded between the
// live-stack check and the stack deletions, which reference a stack this
// drain just deleted.
func takeOrphanedCounts(io drainIO, deleted map[uint32]struct{}) (uint64, error) {
	if len(deleted) == 0 {
		return 0, nil
	}
	var lost uint64
	for _, r := range io.liveCounts() {
		if _, gone := deleted[r.key.StackID]; !gone {
			continue
		}
		var ips [stackDepth]uint64
		if io.lookupStack(r.key.StackID, &ips) == nil {
			continue
		}
		key, count := r.key, r.count
		if err := io.takeCount(&key, &count); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, fmt.Errorf("oncpu: delete orphaned count: %w", err)
		}
		lost += count
	}
	return lost, nil
}

// trimStack cuts the zero padding bpf_get_stackid leaves after the last frame.
func trimStack(ips []uint64) []uint64 {
	n := 0
	for n < len(ips) && ips[n] != 0 {
		n++
	}
	if n == 0 {
		return nil
	}
	return append([]uint64(nil), ips[:n]...)
}

// Sampler holds the per-CPU perf events the sampler program is attached to.
type Sampler struct {
	fds []int
}

// CPUs reports how many CPUs the sampler is running on.
func (s *Sampler) CPUs() int {
	if s == nil {
		return 0
	}
	return len(s.fds)
}

// Close detaches the program from every CPU.
func (s *Sampler) Close() error {
	if s == nil {
		return nil
	}
	var errs []error
	for _, fd := range s.fds {
		if err := closeFD(fd); err != nil {
			errs = append(errs, err)
		}
	}
	s.fds = nil
	return errors.Join(errs...)
}

var onlineCPUsPath = "/sys/devices/system/cpu/online"

// Attach opens a cpu-clock perf event at SampleHz on every online CPU and
// attaches prog to each. A CPU that refuses the event is skipped; the attach
// fails only when no CPU accepts it.
func Attach(prog *ebpf.Program) (*Sampler, error) {
	if prog == nil {
		return nil, errors.New("oncpu: the BPF object has no " + ProgramName + " program")
	}
	return attach(prog.FD())
}

func attach(progFD int) (*Sampler, error) {
	cpus, err := onlineCPUs()
	if err != nil {
		return nil, err
	}
	s := &Sampler{}
	var firstErr error
	for _, cpu := range cpus {
		fd, err := openCPUClock(cpu)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("oncpu: perf_event_open on cpu %d: %w", cpu, err)
			}
			continue
		}
		if err := setBPF(fd, progFD); err != nil {
			_ = closeFD(fd)
			if firstErr == nil {
				firstErr = fmt.Errorf("oncpu: attach to cpu %d: %w", cpu, err)
			}
			continue
		}
		s.fds = append(s.fds, fd)
	}
	if len(s.fds) == 0 {
		return nil, firstErr
	}
	return s, nil
}

// onlineCPUs parses the kernel's online CPU list, such as "0-3,5,7-8".
func onlineCPUs() ([]int, error) {
	raw, err := os.ReadFile(onlineCPUsPath)
	if err != nil {
		return nil, fmt.Errorf("oncpu: read online CPUs: %w", err)
	}
	return parseCPUList(strings.TrimSpace(string(raw)))
}

func parseCPUList(list string) ([]int, error) {
	var cpus []int
	for _, part := range strings.Split(list, ",") {
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("oncpu: CPU list %q: %w", list, err)
		}
		last := first
		if isRange {
			if last, err = strconv.Atoi(hi); err != nil {
				return nil, fmt.Errorf("oncpu: CPU list %q: %w", list, err)
			}
		}
		if last < first {
			return nil, fmt.Errorf("oncpu: CPU list %q: range %d-%d runs backwards", list, first, last)
		}
		for c := first; c <= last; c++ {
			cpus = append(cpus, c)
		}
	}
	if len(cpus) == 0 {
		return nil, fmt.Errorf("oncpu: CPU list %q names no CPU", list)
	}
	return cpus, nil
}

// countIterator is the part of *ebpf.MapIterator liveCounts reads.
type countIterator interface {
	Next(key, value any) bool
}

// liveCounts collects the count rows the iterator holds now.
func liveCounts(it countIterator) []countRow {
	var (
		rows  []countRow
		key   Key
		count uint64
	)
	for it.Next(&key, &count) {
		rows = append(rows, countRow{key: key, count: count})
	}
	return rows
}

// countTaker is the part of *ebpf.Map takeCountFrom uses.
type countTaker interface {
	LookupAndDelete(key, valueOut any) error
	Delete(key any) error
}

// takeCountFrom removes counts atomically with their final value where the
// kernel supports lookup-and-delete on hash maps (5.14+), and falls back to a
// plain delete that keeps the value as iterated.
func takeCountFrom(m countTaker) func(*Key, *uint64) error {
	return func(k *Key, count *uint64) error {
		err := m.LookupAndDelete(k, count)
		if errors.Is(err, ebpf.ErrNotSupported) {
			return m.Delete(k)
		}
		return err
	}
}
