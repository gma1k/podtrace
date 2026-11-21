package diagnose

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

// eventTypeSamplingRates sets how much less likely a full buffer is to keep
// an event of each type than one of rate 1: a type of rate 20 is kept a
// twentieth as often as an OOM kill.
var eventTypeSamplingRates = map[events.EventType]int{
	events.EventOOMKill:        1,
	events.EventNetDevError:    1,
	events.EventTCPRetrans:     5,
	events.EventDNS:            10,
	events.EventPageFault:      10,
	events.EventConnect:        20,
	events.EventConnectResult:  20,
	events.EventHTTPReq:        30,
	events.EventHTTPResp:       30,
	events.EventRequestDone:    30,
	events.EventTCPSend:        50,
	events.EventTCPRecv:        50,
	events.EventUDPSend:        50,
	events.EventUDPRecv:        50,
	events.EventWrite:          100,
	events.EventRead:           100,
	events.EventFsync:          100,
	events.EventSchedSwitch:    200,
	events.EventLockContention: 50,
	events.EventDBQuery:        20,
	events.EventExec:           10,
	events.EventFork:           10,
	events.EventOpen:           100,
	events.EventClose:          100,
	events.EventTCPState:       100,
}

// samplingRate is the rate events of type t are sampled at, at least 1.
func samplingRate(t events.EventType) int {
	rate, ok := eventTypeSamplingRates[t]
	if !ok {
		rate = config.EventSamplingRate
	}
	return max(rate, 1)
}

// The buffer samples by priority. Every event draws u uniformly from [0, 1)
// and gets priority u times its type's rate; the buffer keeps exactly the
// events whose priority is below a threshold. The threshold starts unbounded
// and only falls: when the buffer is full, it drops to the priority that
// keeps the lowest bufferKeepNumerator/bufferKeepDenominator of what is held,
// and events at or above it are let go. An event of rate r therefore ends up
// kept with probability min(1, threshold/r), whenever it arrived and whether
// it succeeded or failed, so a ratio within one type (a failure rate, a
// latency percentile) is that of the whole session, not of whichever events
// happened to arrive before the buffer filled. Events stay in arrival order.
const (
	bufferKeepNumerator   = 3
	bufferKeepDenominator = 4
)

// priority draws the priority of an event of type t.
func (d *Diagnostician) priority(t events.EventType) float64 {
	uniform := d.sampleUniform
	if uniform == nil {
		uniform = d.draws.float64
	}
	return uniform() * float64(samplingRate(t))
}

// compactLocked lowers the threshold so the buffer keeps the lowest
// bufferKeepNumerator/bufferKeepDenominator of its events by priority, and
// lets the rest go, keeping the survivors in order.
func (d *Diagnostician) compactLocked() {
	n := len(d.priorities)
	scratch := append([]float64(nil), d.priorities...)
	d.threshold = nthSmallest(scratch, n*bufferKeepNumerator/bufferKeepDenominator)
	d.sampling = true
	kept := 0
	for i, p := range d.priorities {
		if p >= d.threshold {
			continue
		}
		d.events[kept] = d.events[i]
		d.enrichedEvents[kept] = d.enrichedEvents[i]
		d.priorities[kept] = p
		kept++
	}
	clear(d.events[kept:])
	clear(d.enrichedEvents[kept:])
	d.events = d.events[:kept]
	d.enrichedEvents = d.enrichedEvents[:kept]
	d.priorities = d.priorities[:kept]
	d.droppedEvents += n - kept
}

// nthSmallest returns the value at index k of v were v sorted, reordering v.
// The values are random draws, so a middle pivot needs no defence against
// an adversarial order.
func nthSmallest(v []float64, k int) float64 {
	lo, hi := 0, len(v)-1
	for lo < hi {
		pivot := v[lo+(hi-lo)/2]
		i, j := lo, hi
		for i <= j {
			for v[i] < pivot {
				i++
			}
			for v[j] > pivot {
				j--
			}
			if i <= j {
				v[i], v[j] = v[j], v[i]
				i++
				j--
			}
		}
		switch {
		case k <= j:
			hi = j
		case k >= i:
			lo = i
		default:
			return v[k]
		}
	}
	return v[k]
}

// sampleDraws hands out uniform draws from crypto/rand, read a block at a
// time so a busy buffer does not cost a read per event. A workload cannot
// predict them, so it cannot time its events to be the ones kept.
type sampleDraws struct {
	buf  [512]byte
	left int
}

// next returns 64 uniform bits.
func (s *sampleDraws) next() uint64 {
	if s.left < 8 {
		_, _ = rand.Read(s.buf[:])
		s.left = len(s.buf)
	}
	at := len(s.buf) - s.left
	s.left -= 8
	return binary.LittleEndian.Uint64(s.buf[at:])
}

// float64 returns a uniform draw from [0, 1).
func (s *sampleDraws) float64() float64 {
	return float64(s.next()>>11) / (1 << 53)
}
