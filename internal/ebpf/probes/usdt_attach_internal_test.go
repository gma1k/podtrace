package probes

import (
	"testing"
	"unsafe"
)

func TestUSDTProbeValueLayout(t *testing.T) {
	if got := unsafe.Sizeof(usdtArgValue{}); got != 16 {
		t.Fatalf("usdtArgValue size = %d, want 16 (must match struct usdt_arg in bpf/maps.h)", got)
	}
	if got := unsafe.Sizeof(usdtProbeValue{}); got != 200 {
		t.Fatalf("usdtProbeValue size = %d, want 200 (must match struct usdt_probe in bpf/maps.h)", got)
	}
	if got := unsafe.Offsetof(usdtArgValue{}.Disp); got != 8 {
		t.Fatalf("usdtArgValue.Disp offset = %d, want 8", got)
	}
}

func TestCopyCString(t *testing.T) {
	cases := []struct {
		in   string
		size int
		want string
	}{
		{"provider", 64, "provider"},
		{"", 64, ""},
		{"exactlyfits", 12, "exactlyfits"},
		{"toolongforbuf", 8, "toolong"},
	}
	for _, c := range cases {
		dst := make([]byte, c.size)
		copyCString(dst, c.in)
		n := 0
		for n < len(dst) && dst[n] != 0 {
			n++
		}
		if got := string(dst[:n]); got != c.want {
			t.Errorf("copyCString(%q, %d) = %q, want %q", c.in, c.size, got, c.want)
		}
		if n >= len(dst) {
			t.Errorf("copyCString(%q, %d) not NUL-terminated", c.in, c.size)
		}
	}
}
