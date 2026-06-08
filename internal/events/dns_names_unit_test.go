package events

import "testing"

func TestDNSQTypeName(t *testing.T) {
	cases := map[uint32]string{
		1:    "A",
		28:   "AAAA",
		5:    "CNAME",
		33:   "SRV",
		12:   "PTR",
		16:   "TXT",
		15:   "MX",
		2:    "NS",
		6:    "SOA",
		0:    "lookup",
		9999: "TYPE9999",
	}
	for in, want := range cases {
		if got := dnsQTypeName(in); got != want {
			t.Errorf("dnsQTypeName(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestDNSRCodeName(t *testing.T) {
	cases := map[int32]string{
		0:  "NOERROR",
		1:  "FORMERR",
		2:  "SERVFAIL",
		3:  "NXDOMAIN",
		4:  "NOTIMP",
		5:  "REFUSED",
		42: "rcode 42",
		-1: "rcode -1",
	}
	for in, want := range cases {
		if got := dnsRCodeName(in); got != want {
			t.Errorf("dnsRCodeName(%d) = %q, want %q", in, got, want)
		}
	}
}
