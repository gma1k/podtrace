package dns

import "testing"

func TestARecordSaysWhetherTheKernelAlreadyCountedIt(t *testing.T) {
	b := payloadRecord(map[string]any{"rcode": uint8(2)}, nil)
	r, ok := ParseRecord(b)
	if !ok || r.AggRecorded {
		t.Fatalf("ok %v counted %v for a record the kernel did not count", ok, r.AggRecorded)
	}
	b[57] = 1
	if r, ok = ParseRecord(b); !ok || !r.AggRecorded || r.RCode != 2 {
		t.Errorf("ok %v counted %v rcode %d, want the flag read from byte 57", ok, r.AggRecorded, r.RCode)
	}
}
