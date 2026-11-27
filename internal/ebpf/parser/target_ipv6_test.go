package parser

import (
	"encoding/binary"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestTheKernelsIPv6TargetBecomesABracketedAddressAndPort(t *testing.T) {
	cases := map[string]string{
		"000:000:000:000:000:000:000:001:8086":       "[::1]:8086",
		"2001:db8:000:000:000:000:000:001:443":       "[2001:db8::1]:443",
		"fd00:abcd:1234:5678:9abc:def0:1111:2222:53": "[fd00:abcd:1234:5678:9abc:def0:1111:2222]:53",
		"000:000:000:000:000:ffff:a60:001:443":       "10.96.0.1:443",
		"fe80:000:000:000:000:000:000:001:0":         "[fe80::1]:0",
		"0:0:0:0:0:0:0:1:65535":                      "[::1]:65535",
		"10.96.0.1:443":                              "10.96.0.1:443",
		"/var/lib/data":                              "/var/lib/data",
		"":                                           "",
		"000:000:000:000:000:000:000:001:65536":      "000:000:000:000:000:000:000:001:65536",
		"000:000:000:000:000:000:000:001:08086":      "000:000:000:000:000:000:000:001:08086",
		"000:000:000:000:000:000:000:001:":           "000:000:000:000:000:000:000:001:",
		"000:000:000:000:000:000::001:8086":          "000:000:000:000:000:000::001:8086",
		"000:000:000:000:000:000:00000:001:8086":     "000:000:000:000:000:000:00000:001:8086",
		"000:000:000:000:000:000:xyz:001:8086":       "000:000:000:000:000:000:xyz:001:8086",
		"SELECT a:b:c:d:e:f:g:h:1":                   "SELECT a:b:c:d:e:f:g:h:1",
	}
	for in, want := range cases {
		if got := canonicalIPv6Target(in); got != want {
			t.Errorf("canonicalIPv6Target(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAParsedConnectEventCarriesTheBracketedIPv6Target(t *testing.T) {
	const size = 416
	data := make([]byte, size)
	binary.LittleEndian.PutUint32(data[12:16], uint32(events.EventConnect))
	copy(data[80:], "000:000:000:000:000:000:000:001:8086")

	ev := ParseEvent(data)
	if ev == nil {
		t.Fatal("ParseEvent returned nil")
	}
	if ev.Target != "[::1]:8086" {
		t.Errorf("target = %q, want [::1]:8086", ev.Target)
	}
}
