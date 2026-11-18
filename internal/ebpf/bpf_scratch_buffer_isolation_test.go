package ebpf

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestInterruptContextProgramsFillTheirOwnEventScratch(t *testing.T) {
	cases := []struct{ file, function, slot, acquire, emit string }{
		{"network.c", "tracepoint_inet_sock_set_state", "EVENT_BUF_SOFTIRQ", "event_buf_slot(", "emit_event(e)"},
		{"network.c", "tracepoint_tcp_retransmit_skb", "EVENT_BUF_SOFTIRQ", "event_buf_slot(", "emit_event(e)"},
		{"network.c", "tracepoint_net_dev_xmit", "EVENT_BUF_SOFTIRQ", "event_buf_slot(", "emit_event(e)"},
		{"sockops.c", "sockops_rtt", "EVENT_BUF_SOCKOPS", "event_buf_slot_untracked(", "emit_event_untracked(e)"},
	}
	for _, tc := range cases {
		body := functionBody(t, bpfSource(t, tc.file), tc.function)
		if !strings.Contains(body, tc.emit) {
			t.Errorf("%s:%s must emit with %s", tc.file, tc.function, tc.emit)
		}
		if !strings.Contains(body, tc.acquire+tc.slot+")") {
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

func TestSockOpsUsesNoTaskHelpers(t *testing.T) {
	body := functionBody(t, bpfSource(t, "sockops.c"), "sockops_rtt")
	helpers := bpfSource(t, "helpers.h")
	paths := body + functionBody(t, helpers, "event_buf_slot_untracked") +
		functionBody(t, helpers, "emit_event_untracked")
	for _, helper := range []string{
		"bpf_get_current_pid_tgid", "bpf_get_current_comm", "bpf_get_current_task",
		"bpf_get_current_cgroup_id", "bpf_probe_read_kernel", "get_event_buf",
		"agg_absorbed(",
	} {
		if strings.Contains(paths, helper) {
			t.Errorf("sockops_rtt reaches %s; sock_ops programs have no task context and kernels "+
				"before 7.0 reject the task helpers for this program type", helper)
		}
	}
}

func TestEventScratchMapsHoldOneSlotPerContext(t *testing.T) {
	text := bpfSource(t, "maps.h")
	slots := regexp.MustCompile(`#define EVENT_BUF_(TASK|SOFTIRQ|SOCKOPS|SLOTS)\s+(\d+)`).FindAllStringSubmatch(bpfSource(t, "events.h"), -1)
	values := map[string]int{}
	for _, m := range slots {
		v, _ := strconv.Atoi(m[2])
		values[m[1]] = v
	}
	seen := map[int]string{}
	for _, name := range []string{"TASK", "SOFTIRQ", "SOCKOPS"} {
		v, ok := values[name]
		if !ok {
			t.Fatalf("EVENT_BUF_%s is not defined in events.h", name)
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

var eventEmission = regexp.MustCompile(`\bemit_event\(|bpf_ringbuf_output\(`)

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
			emit := eventEmission.FindStringIndex(text[start:])
			if emit == nil {
				continue
			}
			if strings.Contains(text[start:start+emit[0]], "agg_absorbed") {
				line := strings.Count(text[:start], "\n") + 1
				t.Errorf("%s:%d unwinds the user stack before agg_absorbed decides whether the event is emitted; "+
					"absorbed events fill stack_traces with entries nobody reads", name, line)
			}
		}
	}
}
