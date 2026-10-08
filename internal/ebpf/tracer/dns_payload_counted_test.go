package tracer

import (
	"testing"

	"github.com/gma1k/podtrace/internal/dns"
)

func TestALookupTheKernelCountedIsNotCountedAgainFromItsAnswer(t *testing.T) {
	if e := buildDNSEventFromRecord(dns.Record{RCode: 3, AggRecorded: true}); !e.KernelAggregated {
		t.Error("the answer's event is unmarked, so the metrics plane counts the lookup from both the kernel row and the event")
	}
	if e := buildDNSEventFromRecord(dns.Record{}); e.KernelAggregated {
		t.Error("an answer the kernel did not count was marked as counted, so no one counts it")
	}
}
