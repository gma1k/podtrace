package events

import "testing"

func TestEveryDNSAnswerIsClassedLikeTheKernel(t *testing.T) {
	cases := []struct {
		source uint8
		err    int32
		want   string
		failed bool
	}{
		{DNSSourceUDP, 0, DNSAnswerNoError, false},
		{DNSSourceUDP, 3, DNSAnswerNXDomain, false},
		{DNSSourceUDP, 2, DNSAnswerServFail, true},
		{DNSSourceTCP, 5, DNSAnswerRefused, true},
		{DNSSourceUDP, 1, DNSAnswerOther, true},
		{DNSSourceUDP, 4, DNSAnswerOther, true},
		{DNSSourceUDP, DNSErrorTimeout, DNSAnswerTimeout, true},
		{DNSSourceLibc, 0, DNSAnswerNoError, false},
		{DNSSourceLibc, -2, DNSAnswerNXDomain, false},
		{DNSSourceLibc, -5, DNSAnswerNoError, false},
		{DNSSourceLibc, -3, DNSAnswerServFail, true},
		{DNSSourceLibc, -4, DNSAnswerOther, true},
		{DNSSourceLibc, -11, DNSAnswerOther, true},
	}
	for _, c := range cases {
		e := &Event{Type: EventDNS, DNSTransport: c.source, Error: c.err}
		if got := e.DNSAnswer(); got != c.want {
			t.Errorf("source %d error %d: answer %q, want %q", c.source, c.err, got, c.want)
		}
		if got := e.IsError(); got != c.failed {
			t.Errorf("source %d error %d: IsError %v, want %v", c.source, c.err, got, c.failed)
		}
	}
}

func TestAKernelRowsAnswerClassNamesTheSameAnswers(t *testing.T) {
	want := []string{DNSAnswerNoError, DNSAnswerNXDomain, DNSAnswerServFail, DNSAnswerRefused, DNSAnswerOther}
	for class, answer := range want {
		if got := DNSAnswerOfClass(uint8(class)); got != answer {
			t.Errorf("class %d = %q, want %q", class, got, answer)
		}
	}
	if got := DNSAnswerOfClass(7); got != DNSAnswerOther {
		t.Errorf("an unknown class is %q, want %q", got, DNSAnswerOther)
	}
}

func TestAnEncryptedResolverConnectionIsNotALookup(t *testing.T) {
	e := &Event{Type: EventDNS, DNSTransport: DNSSourceEncrypted}
	if e.IsDNSLookup() || e.CountsAsDNSLookup(false) || e.IsError() {
		t.Error("a DoT/DoH connection has no answer to class and counted as a lookup")
	}
}

func TestAGetaddrinfoCallCountsOnlyWithoutPacketCapture(t *testing.T) {
	e := &Event{Type: EventDNS, DNSTransport: DNSSourceLibc}
	if e.CountsAsDNSLookup(true) {
		t.Error("with packet capture the call's queries are already counted from the wire")
	}
	if !e.CountsAsDNSLookup(false) {
		t.Error("without packet capture the call is the only record of the lookup")
	}
	if (&Event{Type: EventDNSQuery}).CountsAsDNSLookup(false) {
		t.Error("a query is not a lookup until its answer arrives")
	}
}
