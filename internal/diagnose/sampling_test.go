package diagnose

import (
	"cmp"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/events"
)

func rising() func() float64 {
	var n float64
	return func() float64 {
		n++
		return n / (1 << 40)
	}
}

func falling() func() float64 {
	n := float64(1 << 30)
	return func() float64 {
		n--
		return n / (1 << 40)
	}
}

func constant(u float64) func() float64 {
	return func() float64 { return u }
}

func countTypes(d *Diagnostician) map[events.EventType]int {
	c := map[events.EventType]int{}
	for _, e := range d.GetEvents() {
		c[e.Type]++
	}
	return c
}

func TestOnlyTheRareTypesSampleAtRateOne(t *testing.T) {
	for _, typ := range []events.EventType{events.EventOOMKill, events.EventNetDevError} {
		if got := samplingRate(typ); got != 1 {
			t.Errorf("%v rate = %d, want 1", typ, got)
		}
	}
	for _, typ := range []events.EventType{events.EventPageFault, events.EventRequestDone} {
		if got := samplingRate(typ); got <= 1 {
			t.Errorf("%v rate = %d; a type that fires per request or per fault cannot be kept ahead of every other", typ, got)
		}
	}
}

func TestAnUnknownTypeUsesTheConfiguredRateAndNeverLessThanOne(t *testing.T) {
	if got := samplingRate(events.EventType(9999)); got != config.EventSamplingRate {
		t.Errorf("unknown type rate = %d, want %d", got, config.EventSamplingRate)
	}
	orig := config.EventSamplingRate
	config.EventSamplingRate = 0
	t.Cleanup(func() { config.EventSamplingRate = orig })
	if got := samplingRate(events.EventType(9999)); got != 1 {
		t.Errorf("rate with a zero configured rate = %d, want 1", got)
	}
}

func TestThePriorityScalesTheDrawByTheTypesRate(t *testing.T) {
	d := NewDiagnostician()
	d.sampleUniform = constant(0.5)
	for typ, want := range map[events.EventType]float64{
		events.EventDNS:           5,
		events.EventTCPSend:       25,
		events.EventRead:          50,
		events.EventConnectResult: 10,
		events.EventOOMKill:       0.5,
	} {
		if got := d.priority(typ); got != want {
			t.Errorf("%v priority = %v, want %v", typ, got, want)
		}
	}
}

func TestAFullBufferKeepsTheLowestThreeQuartersInArrivalOrder(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 8
	d.sampleUniform = rising()
	for i := range 9 {
		d.AddEvent(&events.Event{Type: events.EventRead, Timestamp: uint64(i + 1)})
	}
	var got []uint64
	for _, e := range d.GetEvents() {
		got = append(got, e.Timestamp)
	}
	if !slices.Equal(got, []uint64{1, 2, 3, 4, 5, 6}) {
		t.Errorf("kept %v, want the six lowest priorities in order", got)
	}
	if d.EventsSampledOut() != 3 || d.EventsSeen() != 9 {
		t.Errorf("sampled out %d of %d, want 3 of 9", d.EventsSampledOut(), d.EventsSeen())
	}
}

func TestAnEventAboveTheThresholdIsLetGoWhileTheBufferHasRoom(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 4
	d.sampleUniform = rising()
	for i := range 5 {
		d.AddEvent(&events.Event{Type: events.EventRead, Timestamp: uint64(i + 1)})
	}
	held := len(d.GetEvents())
	d.AddEvent(&events.Event{Type: events.EventRead, Timestamp: 6})
	if got := len(d.GetEvents()); got != held || held >= d.maxEvents {
		t.Errorf("held %d then %d of %d; an event that would not have survived the last compaction "+
			"must not take a free slot, or later arrivals are kept more often than earlier ones", held, got, d.maxEvents)
	}
}

func TestAnOutageAfterTheBufferFilledShowsItsTrueShareOfTheSession(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1000
	for i := range 1000 {
		d.AddEvent(&events.Event{Type: events.EventConnectResult, Timestamp: uint64(i + 1), Target: "10.0.0.1:80"})
	}
	for i := range 5000 {
		ev := &events.Event{Type: events.EventConnectResult, Timestamp: uint64(2000 + i), Target: "10.0.0.1:80"}
		if i%10 != 0 {
			ev.Error = -111
		}
		d.AddEvent(ev)
	}
	var failed, total int
	for _, e := range d.GetEvents() {
		total++
		if e.Error != 0 {
			failed++
		}
	}
	rate := 100 * float64(failed) / float64(total)
	if rate < 65 || rate > 85 {
		t.Errorf("failure rate = %.1f%% (%d/%d), want about 75%%: 4500 of the session's 6000 connections "+
			"failed, and a buffer weighing the events before it filled above those after shows far less", rate, failed, total)
	}
	var raised bool
	for _, issue := range detector.DetectIssues(d.GetEvents(), 60, config.DefaultRTTThreshold) {
		raised = raised || issue.ID == detector.IDConnectionFailureRate
	}
	if !raised {
		t.Error("a 75% failure rate did not raise the 60% connection-failure issue")
	}
}

func TestAFloodOfOneTypeDoesNotPushTheOthersOut(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1000
	for range 10_000 {
		d.AddEvent(&events.Event{Type: events.EventTCPSend})
	}
	for range 100_000 {
		d.AddEvent(&events.Event{Type: events.EventPageFault})
	}
	c := countTypes(d)
	if c[events.EventTCPSend] < 5 {
		t.Errorf("tcp=%d pagefault=%d: a page-fault flood blinded the report to the traffic before it",
			c[events.EventTCPSend], c[events.EventPageFault])
	}
}

func TestAFullBufferKeepsTheConnectionFailureRate(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 2000

	for i := range 400_000 {
		ev := &events.Event{Type: events.EventConnectResult, Timestamp: uint64(i + 1), Target: "10.0.0.1:80"}
		if i%100 == 0 {
			ev.Error = -111
		}
		d.AddEvent(ev)
	}

	if d.EventsSampledOut() == 0 {
		t.Fatal("the buffer never filled")
	}
	var failed, total int
	for _, e := range d.GetEvents() {
		if e.Type != events.EventConnectResult {
			continue
		}
		total++
		if e.Error != 0 {
			failed++
		}
	}
	rate := float64(failed) / float64(total) * 100
	if rate > 3 {
		t.Errorf("retained failure rate = %.1f%% (%d/%d), want about 1%%", rate, failed, total)
	}
	for _, issue := range detector.DetectIssues(d.GetEvents(), config.DefaultErrorRateThreshold, config.DefaultRTTThreshold) {
		if issue.ID == detector.IDConnectionFailureRate {
			t.Errorf("a 1%% failure rate raised %q once the buffer sampled", issue.Message)
		}
	}
}

func TestAnAlternatingStreamKeepsBothSides(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1000

	for i := range 200_000 {
		typ := events.EventTCPSend
		if i%2 == 1 {
			typ = events.EventTCPRecv
		}
		d.AddEvent(&events.Event{Type: typ, Timestamp: uint64(i + 1)})
	}

	send, recv := len(d.FilterEvents(events.EventTCPSend)), len(d.FilterEvents(events.EventTCPRecv))
	if send == 0 || recv == 0 {
		t.Fatalf("send=%d recv=%d: one side of an alternating stream vanished", send, recv)
	}
	if ratio := float64(send) / float64(recv); ratio < 0.7 || ratio > 1.4 {
		t.Errorf("send/recv = %.2f, want about 1", ratio)
	}
}

func TestASampledBufferCoversTheWholeSessionInOrder(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1000
	const n = 100_000
	for i := range n {
		d.AddEvent(&events.Event{Type: events.EventRead, Timestamp: uint64(i + 1)})
	}
	evs := d.GetEvents()
	if !slices.IsSortedFunc(evs, func(a, b *events.Event) int { return cmp.Compare(a.Timestamp, b.Timestamp) }) {
		t.Fatal("the buffer lost arrival order")
	}
	var early int
	for _, e := range evs {
		if e.Timestamp <= n/2 {
			early++
		}
	}
	if share := float64(early) / float64(len(evs)); share < 0.4 || share > 0.6 {
		t.Errorf("%.0f%% of the kept events come from the first half of the session, want about half", share*100)
	}
	if d.EventsSeen() != n || d.EventsSampledOut()+len(evs) != n {
		t.Errorf("seen %d, sampled out %d, kept %d", d.EventsSeen(), d.EventsSampledOut(), len(evs))
	}
}

func TestNthSmallestMatchesASort(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for _, size := range []int{1, 2, 3, 7, 64, 1000} {
		for range 20 {
			v := make([]float64, size)
			for i := range v {
				v[i] = float64(r.IntN(size/2 + 1))
			}
			sorted := slices.Sorted(slices.Values(v))
			k := r.IntN(size)
			if got := nthSmallest(slices.Clone(v), k); got != sorted[k] {
				t.Fatalf("nthSmallest(%v, %d) = %v, want %v", v, k, got, sorted[k])
			}
		}
	}
}

func TestDrawsAreUniformInTheUnitIntervalAcrossRefills(t *testing.T) {
	var draws sampleDraws
	bins := make([]int, 10)
	for range 10_000 {
		v := draws.float64()
		if v < 0 || v >= 1 {
			t.Fatalf("draw %v outside [0, 1)", v)
		}
		bins[int(v*10)]++
	}
	for b, n := range bins {
		if n < 800 || n > 1200 {
			t.Errorf("bin %d drew %d of 10000, want about 1000", b, n)
		}
	}
}
