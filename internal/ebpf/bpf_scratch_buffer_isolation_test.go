package ebpf

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestInterruptContextProgramsFillTheirOwnEventScratch(t *testing.T) {
	cases := []struct{ file, function, slot string }{
		{"network.c", "tracepoint_inet_sock_set_state", "EVENT_BUF_SOFTIRQ"},
		{"network.c", "tracepoint_tcp_retransmit_skb", "EVENT_BUF_SOFTIRQ"},
		{"network.c", "tracepoint_net_dev_xmit", "EVENT_BUF_SOFTIRQ"},
		{"sockops.c", "sockops_rtt", "EVENT_BUF_SOCKOPS"},
	}
	for _, tc := range cases {
		body := functionBody(t, bpfSource(t, tc.file), tc.function)
		if !strings.Contains(body, "event_buf_slot("+tc.slot+")") {
			t.Errorf("%s:%s runs in softirq and can interrupt a uprobe or fexit handler mid-fill; "+
				"it must fill the %s scratch slot, not the task slot", tc.file, tc.function, tc.slot)
		}
		if strings.Contains(body, "get_event_buf") {
			t.Errorf("%s:%s must not use the task-context event scratch", tc.file, tc.function)
		}
	}
	if !strings.Contains(functionBody(t, bpfSource(t, "network.c"), "socket_event_context"),
		"capture_user_stack_slot(ctx, cur_pid, 0, e, EVENT_BUF_SOFTIRQ)") {
		t.Error("socket_event_context runs in softirq; it must unwind into the softirq stack scratch slot")
	}
}

func TestEventScratchMapsHoldOneSlotPerContext(t *testing.T) {
	text := bpfSource(t, "maps.h")
	slots := regexp.MustCompile(`#define EVENT_BUF_(TASK|SOFTIRQ|SOCKOPS|SLOTS)\s+(\d+)`).FindAllStringSubmatch(text, -1)
	values := map[string]int{}
	for _, m := range slots {
		v, _ := strconv.Atoi(m[2])
		values[m[1]] = v
	}
	seen := map[int]string{}
	for _, name := range []string{"TASK", "SOFTIRQ", "SOCKOPS"} {
		v, ok := values[name]
		if !ok {
			t.Fatalf("EVENT_BUF_%s is not defined in maps.h", name)
		}
		if v >= values["SLOTS"] {
			t.Errorf("EVENT_BUF_%s = %d does not fit in EVENT_BUF_SLOTS = %d", name, v, values["SLOTS"])
		}
		if other, dup := seen[v]; dup {
			t.Errorf("EVENT_BUF_%s and EVENT_BUF_%s share scratch slot %d", name, other, v)
		}
		seen[v] = name
	}
	for _, name := range []string{"event_buf", "stack_buf"} {
		block, ok := mapBlock(text, name)
		if !ok {
			t.Fatalf("map %q not found in maps.h", name)
		}
		if !strings.Contains(block, "__uint(max_entries, EVENT_BUF_SLOTS)") {
			t.Errorf("map %q must have one entry per scratch slot", name)
		}
	}
}

func TestUserStacksAreCapturedOnlyForEmittedEvents(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(locateBPFDir(t), "*.c"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		name := filepath.Base(path)
		text := bpfSource(t, name)
		offset := 0
		for {
			i := strings.Index(text[offset:], "capture_user_stack(")
			if i < 0 {
				break
			}
			start := offset + i
			offset = start + 1
			emit := strings.Index(text[start:], "bpf_ringbuf_output(")
			if emit < 0 {
				continue
			}
			if strings.Contains(text[start:start+emit], "agg_absorbed(") {
				line := strings.Count(text[:start], "\n") + 1
				t.Errorf("%s:%d unwinds the user stack before agg_absorbed decides whether the event is emitted; "+
					"absorbed events fill stack_traces with entries nobody reads", name, line)
			}
		}
	}
}
