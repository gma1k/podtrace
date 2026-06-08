package dns

import "testing"

func TestItoa(t *testing.T) {
	tests := []struct {
		in   byte
		want string
	}{
		{0, "0"},
		{1, "1"},
		{9, "9"},
		{10, "10"},
		{99, "99"},
		{100, "100"},
		{255, "255"},
	}
	for _, tt := range tests {
		if got := itoa(tt.in); got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIPv4String_WithZeroOctets(t *testing.T) {
	if got := ipv4String([]byte{0, 0, 0, 0}); got != "0.0.0.0" {
		t.Errorf("ipv4String(0.0.0.0) = %q", got)
	}
	if got := ipv4String([]byte{10, 0, 0, 1}); got != "10.0.0.1" {
		t.Errorf("ipv4String(10.0.0.1) = %q", got)
	}
	if got := ipv4String([]byte{192, 168, 1, 255}); got != "192.168.1.255" {
		t.Errorf("ipv4String = %q", got)
	}
}
