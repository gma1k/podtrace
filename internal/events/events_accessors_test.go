package events

import "testing"

func TestPeerIP(t *testing.T) {
	loopbackV6 := [16]byte{15: 1}
	globalV6 := [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	zeroV6 := [16]byte{}

	cases := []struct {
		name   string
		family uint8
		v4     uint32
		v6     [16]byte
		want   string
	}{
		{"AF_INET zero returns empty", 2, 0, zeroV6, ""},
		{"AF_INET formats big-endian", 2, 0x7f000001, zeroV6, "127.0.0.1"},
		{"AF_INET 10.0.0.1", 2, 0x0a000001, zeroV6, "10.0.0.1"},
		{"AF_INET6 unspecified returns empty", 10, 0, zeroV6, ""},
		{"AF_INET6 loopback", 10, 0, loopbackV6, "::1"},
		{"AF_INET6 global", 10, 0, globalV6, "fd00::1"},
		{"unknown family returns empty", 0, 0x7f000001, globalV6, ""},
		{"AF_UNIX-ish family returns empty", 1, 0x7f000001, globalV6, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := PeerIP(c.family, c.v4, c.v6); got != c.want {
				t.Errorf("PeerIP(%d, %#x, %v) = %q, want %q", c.family, c.v4, c.v6, got, c.want)
			}
		})
	}
}

func TestCutRunes(t *testing.T) {
	cases := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"n zero returns empty", "abc", 0, ""},
		{"n negative returns empty", "abc", -3, ""},
		{"n at length returns whole", "abc", 3, "abc"},
		{"n past length returns whole", "abc", 9, "abc"},
		{"ascii cut mid-string", "abcdef", 3, "abc"},
		{"backs off multibyte boundary", "café", 4, "caf"},
		{"cut exactly before multibyte", "café", 3, "caf"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cutRunes(c.s, c.n); got != c.want {
				t.Errorf("cutRunes(%q, %d) = %q, want %q", c.s, c.n, got, c.want)
			}
		})
	}
}

func TestHTTPProtoLabel_TLSOnly(t *testing.T) {
	e := &Event{Type: EventHTTPReq, TCPState: HTTPTransportTLS}
	if got := e.HTTPProtoLabel(); got != "HTTPS" {
		t.Errorf("HTTPProtoLabel() = %q, want HTTPS", got)
	}
	if got := e.HTTPScheme(); got != "https" {
		t.Errorf("HTTPScheme() = %q, want https", got)
	}
	if got := e.TypeString(); got != "HTTPS" {
		t.Errorf("TypeString() = %q, want HTTPS", got)
	}
}

func TestTypeString_RemainingTypes(t *testing.T) {
	cases := []struct {
		et   EventType
		want string
	}{
		{EventDNSQuery, "DNS"},
		{EventHTTP3, "HTTP/3"},
		{EventUSDT, "USDT"},
	}
	for _, c := range cases {
		e := &Event{Type: c.et}
		if got := e.TypeString(); got != c.want {
			t.Errorf("TypeString(%d) = %q, want %q", c.et, got, c.want)
		}
	}
}

func TestDNSServerAddr_IPv6(t *testing.T) {
	e := &Event{

		DNSServerIP6: [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DNSServerIP:  0x0a00600a,
	}
	want := "fd00:0000:0000:0000:0000:0000:0000:0001"
	if got := e.DNSServerAddr(); got != want {
		t.Errorf("DNSServerAddr() = %q, want %q", got, want)
	}

	e2 := &Event{DNSServerIP6: [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88}}
	want2 := "2001:4860:4860:0000:0000:0000:0000:8888"
	if got := e2.DNSServerAddr(); got != want2 {
		t.Errorf("DNSServerAddr() = %q, want %q", got, want2)
	}
}

func TestEvent_DNSQueryType(t *testing.T) {
	cases := map[uint32]string{
		1:    "A",
		28:   "AAAA",
		15:   "MX",
		0:    "lookup",
		4242: "TYPE4242",
	}
	for qtype, want := range cases {
		e := &Event{TCPState: qtype}
		if got := e.DNSQueryType(); got != want {
			t.Errorf("DNSQueryType() for TCPState=%d = %q, want %q", qtype, got, want)
		}
	}
}

func TestEvent_DNSResponseCode(t *testing.T) {
	cases := map[int32]string{
		0:  "NOERROR",
		3:  "NXDOMAIN",
		5:  "REFUSED",
		99: "rcode 99",
	}
	for rcode, want := range cases {
		e := &Event{Error: rcode}
		if got := e.DNSResponseCode(); got != want {
			t.Errorf("DNSResponseCode() for Error=%d = %q, want %q", rcode, got, want)
		}
	}
}
