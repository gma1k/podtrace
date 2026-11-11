package probes

import "testing"

func TestEveryVectoredSyscallIsTracedAtBothEnds(t *testing.T) {
	attached := map[string]string{}
	for _, tp := range tracepointProbes {
		if tp.category == "syscalls" {
			attached[tp.event] = tp.prog
		}
	}
	for _, io := range vectoredIO {
		exit := "tracepoint_sys_exit_fs_read"
		if io.write {
			exit = "tracepoint_sys_exit_fs_write"
		}
		if got := attached["sys_enter_"+io.syscall]; got != "tracepoint_sys_enter_fs_rw" {
			t.Errorf("sys_enter_%s -> %q", io.syscall, got)
		}
		if got := attached["sys_exit_"+io.syscall]; got != exit {
			t.Errorf("sys_exit_%s -> %q, want %s", io.syscall, got, exit)
		}
	}
	for _, prog := range []string{"tracepoint_sys_enter_fs_rw", "tracepoint_sys_exit_fs_read", "tracepoint_sys_exit_fs_write"} {
		if GroupForProbe(prog) != GroupFileSystem {
			t.Errorf("%s is not in the filesystem group", prog)
		}
	}
}

func TestAVectoredSyscallsExitIsAttachedBeforeItsEntry(t *testing.T) {
	position := map[string]int{}
	for i, tp := range tracepointProbes {
		position[tp.event] = i
	}
	for _, io := range vectoredIO {
		if position["sys_exit_"+io.syscall] > position["sys_enter_"+io.syscall] {
			t.Errorf("%s: entry attached before exit, so a call in flight at attach would leave its start behind", io.syscall)
		}
	}
}
