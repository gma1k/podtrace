package main

import (
	"context"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/diagnose"
	"github.com/gma1k/podtrace/internal/events"
)

func runFilter(t *testing.T, filter string, in []events.EventType) map[events.EventType]bool {
	t.Helper()
	src := make(chan *events.Event, len(in))
	dst := make(chan *events.Event, len(in))
	for _, et := range in {
		src <- &events.Event{Type: et}
	}
	close(src)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filterEvents(ctx, src, dst, filter)
	got := map[events.EventType]bool{}
	for ev := range dst {
		got[ev.Type] = true
	}
	return got
}

func TestCLIFilterKeepsEventsTheAgentKeeps(t *testing.T) {
	cases := map[string][]events.EventType{
		"dns":  {events.EventDNSQuery},
		"net":  {events.EventConnectResult, events.EventUDPSend, events.EventUDPRecv, events.EventTCPState, events.EventTCPRetrans, events.EventTCPRTT, events.EventNetDevError, events.EventDBQuery, events.EventRedisCmd, events.EventKafkaFetch, events.EventPoolExhausted, events.EventTLSError},
		"fs":   {events.EventUnlink, events.EventRename, events.EventOpen, events.EventClose},
		"cpu":  {events.EventLockContention},
		"proc": {events.EventOOMKill, events.EventPageFault, events.EventResourceLimit},
	}
	for filter, want := range cases {
		t.Run(filter, func(t *testing.T) {
			got := runFilter(t, filter, want)
			for _, et := range want {
				if !got[et] {
					e := &events.Event{Type: et}
					t.Errorf("--filter %s dropped %s", filter, e.TypeString())
				}
			}
		})
	}
}

func TestCLIProcFilterNoLongerClaimsOpenAndClose(t *testing.T) {
	got := runFilter(t, "proc", []events.EventType{events.EventOpen, events.EventClose, events.EventExec})
	if got[events.EventOpen] || got[events.EventClose] || !got[events.EventExec] {
		t.Fatalf("proc filter delivered %v", got)
	}
}

func TestSessionSummaryCountsByFilterCategory(t *testing.T) {
	d := diagnose.NewDiagnostician()
	for _, et := range []events.EventType{
		events.EventHTTPReq, events.EventGRPCMethod, events.EventDBQuery,
		events.EventLockContention, events.EventOpen, events.EventOOMKill,
		events.EventRequestDone, events.EventAFALG,
	} {
		d.AddEvent(&events.Event{Type: et})
	}
	d.Finish()

	s := computeSessionSummary(d, "node-a")
	if s.TotalEvents != 8 || s.NetEvents != 3 || s.CPUEvents != 1 || s.FSEvents != 1 || s.ProcEvents != 1 || s.DNSEvents != 0 {
		t.Fatalf("summary = %+v", s)
	}
}
