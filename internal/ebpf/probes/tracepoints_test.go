package probes

import "testing"

// TestTracepointProbes_TargetsExistUpstream is a regression test for two
// silent dead probes: tcp:tcp_set_state was removed in kernel 4.16 (replaced
// by sock:inet_sock_set_state) and oom:oom_kill_process never existed
// upstream (the oom group exposes mark_victim). Both were registered with the
// removed/nonexistent names, so the attach failed silently on every mainline
// kernel and EVENT_TCP_STATE / EVENT_OOM_KILL were never produced.
func TestTracepointProbes_TargetsExistUpstream(t *testing.T) {
	byProgram := make(map[string]tracepointSpec, len(tracepointProbes))
	for _, tp := range tracepointProbes {
		byProgram[tp.prog] = tp
	}

	for program, want := range map[string]struct{ category, event string }{
		"tracepoint_inet_sock_set_state": {"sock", "inet_sock_set_state"},
		"tracepoint_oom_mark_victim":     {"oom", "mark_victim"},
	} {
		tp, ok := byProgram[program]
		if !ok {
			t.Errorf("tracepointProbes is missing program %q", program)
			continue
		}
		if tp.category != want.category || tp.event != want.event {
			t.Errorf("%s targets %s/%s, want %s/%s", program, tp.category, tp.event, want.category, want.event)
		}
	}

	for _, removed := range []string{"tracepoint_tcp_set_state", "tracepoint_oom_kill_process"} {
		if _, ok := byProgram[removed]; ok {
			t.Errorf("tracepointProbes still registers %q, whose tracepoint does not exist on mainline kernels", removed)
		}
	}
}

// TestTracepointProbes_NoSilentFailures: an empty failMsg suppressed the
// attach-failure log line entirely, which is how the two dead tracepoints
// above went unnoticed. Every tracepoint must carry a message.
func TestTracepointProbes_NoSilentFailures(t *testing.T) {
	for _, tp := range tracepointProbes {
		if tp.failMsg == "" {
			t.Errorf("tracepoint %s/%s (%s) has an empty failMsg; attach failures would be silent", tp.category, tp.event, tp.prog)
		}
	}
}
