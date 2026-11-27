package ebpf

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
)

func TestBypassExceptL7ModeMatchesTheGoConstant(t *testing.T) {
	want := fmt.Sprintf("#define AGG_MODE_BYPASS_EXCEPT_L7 %d", kernelagg.ModeBypassExceptL7)
	if !strings.Contains(bpfSource(t, "agg.h"), want) {
		t.Errorf("agg.h must define %q to match kernelagg.ModeBypassExceptL7", want)
	}
}

func TestBypassExceptL7ShipsOnlyTheResponsesSemconvReads(t *testing.T) {
	agg := bpfSource(t, "agg.h")
	if !strings.Contains(functionBody(t, agg, "agg_absorbed_checked"), "return agg_mode_absorbs(e);") {
		t.Error("agg_absorbed_checked must take the bypass decision from agg_mode_absorbs")
	}
	absorbs := functionBody(t, agg, "agg_mode_absorbs")
	for _, want := range []string{
		"if (mode == AGG_MODE_BYPASS)\n\t\treturn 1;",
		"if (mode == AGG_MODE_BYPASS_EXCEPT_L7)\n\t\treturn !agg_l7_detail_wanted(e);",
		"return 0;",
	} {
		if !strings.Contains(absorbs, want) {
			t.Errorf("agg_mode_absorbs lacks %q", want)
		}
	}

	wanted := functionBody(t, agg, "agg_l7_detail_wanted")
	for _, eventType := range []string{"EVENT_HTTP_RESP", "EVENT_GRPC_METHOD", "EVENT_REDIS_CMD", "EVENT_MEMCACHED_CMD", "EVENT_DB_QUERY"} {
		if !strings.Contains(wanted, "case "+eventType+":") {
			t.Errorf("agg_l7_detail_wanted does not ship %s, so its semantic-convention family stays empty", eventType)
		}
	}
	for _, eventType := range []string{"EVENT_TCP_SEND", "EVENT_KAFKA_PRODUCE", "EVENT_KAFKA_FETCH", "EVENT_FASTCGI_RESPONSE", "EVENT_HTTP3"} {
		if strings.Contains(wanted, "case "+eventType+":") {
			t.Errorf("agg_l7_detail_wanted ships %s, which no semantic-convention family reads", eventType)
		}
	}
	if !strings.Contains(wanted, "(e->tcp_state & HTTP_ROLE_MASK) != HTTP_ROLE_KNOWN") {
		t.Error("client-side HTTP and gRPC responses must stay bypassed, matching Event.IsClientL7Response")
	}
}

func TestFilesystemEventsFollowTheSameBypassAsEveryOtherEvent(t *testing.T) {
	emit := functionBody(t, bpfSource(t, "filesystem.h"), "fs_emit")
	if !strings.Contains(emit, "if (recorded && agg_mode_absorbs(e))\n\t\treturn;") {
		t.Error("fs_emit must drop a recorded event in every mode that absorbs it, " +
			"or bypass-except-L7 still ships every slow read and every close to userspace")
	}
	if strings.Contains(emit, "AGG_MODE_BYPASS") {
		t.Error("fs_emit must not keep its own list of bypass modes")
	}
}
