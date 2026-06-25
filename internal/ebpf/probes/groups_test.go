package probes

import "testing"

func TestGroupForProbe_HTTPSocketProbes(t *testing.T) {
	for _, prog := range []string{
		"kprobe_http_tcp_sendmsg",
		"kprobe_http_tcp_recvmsg",
		"kretprobe_http_tcp_recvmsg",
	} {
		if got := GroupForProbe(prog); got != GroupNetwork {
			t.Errorf("GroupForProbe(%q) = %q, want %q", prog, got, GroupNetwork)
		}
	}
}

func TestGroupForProbe_UnknownDefaultsToNetwork(t *testing.T) {
	if got := GroupForProbe("kprobe_does_not_exist"); got != GroupNetwork {
		t.Errorf("GroupForProbe(unknown) = %q, want %q", got, GroupNetwork)
	}
}