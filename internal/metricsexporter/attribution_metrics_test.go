package metricsexporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestRecordAttribution_IncrementsLabeledCounter guards the exact label
// values the ingest path passes: a fat-fingered source or event label
// would land on a different (or invalid) series and this would catch it.
func TestRecordAttribution_IncrementsLabeledCounter(t *testing.T) {
	cases := []struct{ source, event string }{
		{"event_comm", "other"},
		{"correlator", "dns"},
		{"proc_fallback", "dns"},
		{"correlator", "quic"},
		{"none", "quic"},
	}
	for _, c := range cases {
		before := testutil.ToFloat64(attributionCounter.WithLabelValues(c.source, c.event))
		RecordAttribution(c.source, c.event)
		after := testutil.ToFloat64(attributionCounter.WithLabelValues(c.source, c.event))
		if after-before != 1 {
			t.Errorf("attribution_total{source=%q,event=%q} delta = %v, want 1",
				c.source, c.event, after-before)
		}
	}
}

func TestRecordAttributionPidReuseSuspected_Increments(t *testing.T) {
	before := testutil.ToFloat64(attributionPidReuseCounter)
	RecordAttributionPidReuseSuspected()
	RecordAttributionPidReuseSuspected()
	after := testutil.ToFloat64(attributionPidReuseCounter)
	if after-before != 2 {
		t.Errorf("pid_reuse_suspected delta = %v, want 2", after-before)
	}
}
