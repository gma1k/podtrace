package probes

import "testing"

func TestGroupForProbe_Crypto(t *testing.T) {
	if g := GroupForProbe("tracepoint_sys_enter_bind"); g != GroupCrypto {
		t.Errorf("GroupForProbe(tracepoint_sys_enter_bind) = %v, want %v", g, GroupCrypto)
	}
}

func TestTracepointProbes_IncludesBind(t *testing.T) {
	found := false
	for _, tp := range tracepointProbes {
		if tp.prog == "tracepoint_sys_enter_bind" {
			found = true
			if tp.category != "syscalls" || tp.event != "sys_enter_bind" {
				t.Errorf("bind tracepoint wired to %s/%s, want syscalls/sys_enter_bind", tp.category, tp.event)
			}
		}
	}
	if !found {
		t.Error("tracepoint_sys_enter_bind missing from tracepointProbes — it will never attach")
	}
}
