package ebpf

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestKernelAggregationSkipsTheRestartCodesUserspaceSkips(t *testing.T) {
	common := bpfSource(t, "common.h")
	define := func(name string) int32 {
		m := regexp.MustCompile(`(?m)^#define ` + name + ` (\d+)$`).FindStringSubmatch(common)
		if m == nil {
			t.Fatalf("common.h does not define %s", name)
		}
		v, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatal(err)
		}
		return int32(v)
	}
	low, high := define("ERESTARTSYS"), define("ERESTART_RESTARTBLOCK")

	agg := bpfSource(t, "agg.h")
	if !strings.Contains(functionBody(t, agg, "errno_is_kernel_restart"), "return err <= -ERESTARTSYS && err >= -ERESTART_RESTARTBLOCK;") {
		t.Error("errno_is_kernel_restart must cover -ERESTARTSYS through -ERESTART_RESTARTBLOCK")
	}
	if !strings.Contains(functionBody(t, agg, "agg_from_event"), "if (e->error != 0 && !errno_is_kernel_restart(e->error))\n\t\tis_error = 1;") {
		t.Error("agg_from_event must not count a kernel restart code as an error")
	}

	for code := low - 1; code <= high+1; code++ {
		inKernelRange := code >= low && code <= high
		e := events.Event{Type: events.EventUDPRecv, Error: -code}
		if e.IsError() == inKernelRange {
			t.Errorf("error -%d: userspace IsError = %v but the kernel range says restart = %v; the two paths disagree", code, e.IsError(), inKernelRange)
		}
	}
}
