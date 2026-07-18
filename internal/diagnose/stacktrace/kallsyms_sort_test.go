package stacktrace

import (
	"testing"
)

func TestSortKsyms_OrdersByAddress(t *testing.T) {
	in := []ksym{
		{Addr: 0x30, Name: "c"},
		{Addr: 0x10, Name: "a"},
		{Addr: 0x10, Name: "a_alias"},
		{Addr: 0x20, Name: "b"},
		{Addr: 0x00, Name: "zero"},
	}
	sortKsyms(in)
	if !isSorted(in) {
		t.Fatalf("sortKsyms did not produce address-sorted output: %+v", in)
	}
	if in[0].Addr != 0x00 || in[len(in)-1].Addr != 0x30 {
		t.Errorf("unexpected bounds after sort: %+v", in)
	}
}

func TestSortKsyms_LargeInputIsFast(t *testing.T) {
	const n = 500_000
	syms := make([]ksym, n)
	for i := range syms {
		syms[i] = ksym{Addr: uint64(n - i), Name: "s"}
	}
	sortKsyms(syms)
	if !isSorted(syms) {
		t.Fatal("large input not sorted")
	}
}
