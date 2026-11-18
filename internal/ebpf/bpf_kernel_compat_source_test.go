package ebpf

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func bpfFiles(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, pattern := range []string{"*.c", "*.h"} {
		files, err := filepath.Glob(filepath.Join(locateBPFDir(t), pattern))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if filepath.Base(f) != "vmlinux.h" {
				names = append(names, filepath.Base(f))
			}
		}
	}
	return names
}

func TestEventsAreEmittedThroughTheSlotOwnershipCheck(t *testing.T) {
	for _, name := range bpfFiles(t) {
		if name == "helpers.h" {
			continue
		}
		if strings.Contains(bpfSource(t, name), "bpf_ringbuf_output(&events,") {
			t.Errorf("%s writes the events ring buffer directly; use emit_event "+
				"so a record whose scratch slot was reused by a preempting task is discarded", name)
		}
	}
}

func TestEventSlotOwnerIsClaimedBeforeTheBufferIsTouched(t *testing.T) {
	body := functionBody(t, bpfSource(t, "helpers.h"), "event_buf_slot")
	claim := strings.Index(body, "s->owner = bpf_get_current_pid_tgid();")
	clear := strings.Index(body, "__builtin_memset(e, 0")
	if claim < 0 || clear < 0 || claim > clear {
		t.Error("event_buf_slot must record the owning task before it clears the slot, " +
			"otherwise a preempted owner cannot notice the slot was taken")
	}
	emit := functionBody(t, bpfSource(t, "helpers.h"), "emit_event")
	copied := strings.Index(emit, "bpf_probe_read_kernel(rec")
	checked := strings.Index(emit, "event_buf_intact(e)")
	if copied < 0 || checked < 0 || checked < copied {
		t.Error("emit_event must verify ownership after copying into the reserved record")
	}
	if !strings.Contains(functionBody(t, bpfSource(t, "agg.h"), "agg_absorbed_checked"), "tracked && !event_buf_intact(e)") {
		t.Error("agg_absorbed must not fold a record whose slot was taken by another task")
	}
	maps := bpfSource(t, "maps.h")
	if !regexp.MustCompile(`struct event_slot \{\s*struct event e;\s*u64 owner;\s*u64 races;\s*\};`).MatchString(maps) {
		t.Error("struct event_slot must be {event, owner, races}; the agent reads races as the last 8 bytes")
	}
}

func TestKfuncsAreOptional(t *testing.T) {
	extern := regexp.MustCompile(`extern [^;]*\b(\w+)\([^;]*\)\s*__ksym([^;]*);`)
	for _, name := range bpfFiles(t) {
		text := bpfSource(t, name)
		for _, m := range extern.FindAllStringSubmatch(text, -1) {
			if !strings.Contains(m[2], "__weak") {
				t.Errorf("%s: kfunc %s is not __weak; a kernel without it fails the whole collection", name, m[1])
			}
			if !strings.Contains(text, "bpf_ksym_exists("+m[1]+")") {
				t.Errorf("%s: kfunc %s is called without a bpf_ksym_exists guard", name, m[1])
			}
		}
	}
}

func TestIovIterIsReadOnlyThroughTheVersionedHelpers(t *testing.T) {
	raw := regexp.MustCompile(`msg_iter\.(__iov|ubuf|iov)\b|[=!]=\s*ITER_(UBUF|IOVEC)\b|->__iov\b`)
	for _, name := range bpfFiles(t) {
		if name == "protocols.h" {
			continue
		}
		if loc := raw.FindStringIndex(bpfSource(t, name)); loc != nil {
			t.Errorf("%s reads iov_iter directly (%q); the field names and the iter_type numbering "+
				"differ before 6.4, so go through msghdr_user_base or msghdr_iovec",
				name, bpfSource(t, name)[loc[0]:loc[1]])
		}
	}
	text := bpfSource(t, "protocols.h")
	for _, want := range []string{
		"struct iov_iter___pre64",
		"bpf_core_field_exists(iter->__iov)",
		"bpf_core_enum_value_exists(enum iter_type, ITER_UBUF)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("protocols.h lost the pre-6.4 iov_iter fallback %q", want)
		}
	}
}

func TestCompatVariantsDropOnlyTheNewerKernelFeature(t *testing.T) {
	cases := []struct{ file, preferred, compat, run string }{
		{"dns.c", "dns_egress", "dns_egress__compat", "dns_egress_run(skb, %d)"},
		{"http3.c", "http3_egress", "http3_egress__compat", "http3_egress_run(skb, %d)"},
		{"memory.c", "tracepoint_oom_mark_victim", "tracepoint_oom_mark_victim__compat", "oom_mark_victim(ctx, %d)"},
	}
	for _, tc := range cases {
		text := bpfSource(t, tc.file)
		if !strings.Contains(functionBody(t, text, tc.preferred), fmt.Sprintf(tc.run, 1)) {
			t.Errorf("%s must run with the newer kernel feature enabled", tc.preferred)
		}
		if !strings.Contains(functionBody(t, text, tc.compat), fmt.Sprintf(tc.run, 0)) {
			t.Errorf("%s must run the same body with the newer kernel feature disabled", tc.compat)
		}
	}
	if !strings.Contains(functionBody(t, bpfSource(t, "memory.c"), "oom_mark_victim"),
		"if (use_kfunc && bpf_ksym_exists(bpf_task_from_pid)") {
		t.Error("the OOM compat variant must not reach the kfunc call")
	}
	for _, name := range []string{"emit_encrypted_dns", "dns_egress_run"} {
		if !strings.Contains(functionBody(t, bpfSource(t, "dns.c"), name), "task_pid ? agent_ns_tgid() : 0") {
			t.Errorf("%s must skip the task helpers when task_pid is off", name)
		}
	}
}
