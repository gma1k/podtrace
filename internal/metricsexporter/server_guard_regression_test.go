package metricsexporter

import (
	"testing"
)

// TestAddrIsLoopback: the old bind guard only fired when the host parsed
// as a non-loopback IP. ":9090" (empty host = every interface), hostnames,
// and unparsable addresses all skipped the guard and bound publicly on a
// privileged pod.
func TestAddrIsLoopback(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:9090", true},
		{"[::1]:9090", true},
		{"localhost:9090", true},
		{"LOCALHOST:9090", true},
		{":9090", false},
		{"0.0.0.0:9090", false},
		{"10.0.0.5:9090", false},
		{"metrics.internal:9090", false},
		{"not-an-addr", false},
	}
	for _, c := range cases {
		if got := addrIsLoopback(c.addr); got != c.want {
			t.Errorf("addrIsLoopback(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}
