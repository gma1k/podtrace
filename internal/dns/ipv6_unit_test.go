package dns

import (
	"net"
	"testing"
)

func TestIPv6String(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "all zeros",
			in:   make([]byte, 16),
			want: "0000:0000:0000:0000:0000:0000:0000:0000",
		},
		{
			name: "loopback ::1",
			in:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want: "0000:0000:0000:0000:0000:0000:0000:0001",
		},
		{
			name: "full address",
			in: []byte{
				0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
				0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
			},
			want: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipv6String(tt.in); got != tt.want {
				t.Errorf("ipv6String(%v) = %q, want %q", tt.in, got, tt.want)
			}
			parsed := net.ParseIP(tt.want)
			if parsed == nil {
				t.Fatalf("net.ParseIP(%q) returned nil", tt.want)
			}
			if to16 := parsed.To16(); !equalBytes(to16, tt.in) {
				t.Errorf("net.ParseIP(%q).To16() = %v, want %v", tt.want, to16, tt.in)
			}
		})
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
