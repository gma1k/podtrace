package blocklist

import (
	"net"
	"testing"
)

func TestIsBlocked(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"169.254.169.254", true},
		{"fe80::1", true},
		{"0.0.0.0", true},
		{"::", true},
		{"224.0.0.1", true},
		{"ff02::1", true},
		{"fd00:ec2::254", true},
		{"100.100.100.200", true},
		{"168.63.129.16", true},
		{"::ffff:169.254.169.254", true},
		{"64:ff9b::a9fe:a9fe", true},
		{"::a9fe:a9fe", true},
		{"10.0.0.1", false},
		{"8.8.8.8", false},
		{"::1", false},
		{"64:ff9b::808:808", false},
	}
	for _, tc := range cases {
		if got := IsBlocked(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("IsBlocked(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if !IsBlocked(nil) {
		t.Error("a nil IP must be blocked")
	}
}

func TestIsBlockedHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"otel-collector.observability.svc", false},
		{"10.0.0.1", false},
		{"168.63.129.16", true},
		{"fe80::1%eth0", true},
		{"fd00::1%eth0", true},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsBlockedHost(tc.host); got != tc.want {
			t.Errorf("IsBlockedHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
