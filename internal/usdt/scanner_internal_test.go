package usdt

import "testing"

// TestCstring_NoNullTerminator tests the false path of cstring (no null found).
func TestCstring_NoNullTerminator(t *testing.T) {
	b := []byte{'a', 'b', 'c'} // no null terminator
	s, rest, ok := cstring(b)
	if ok {
		t.Errorf("expected ok=false for no-null input, got s=%q rest=%v", s, rest)
	}
	if s != "" || rest != nil {
		t.Errorf("expected empty s and nil rest, got s=%q rest=%v", s, rest)
	}
}

// TestCstring_EmptySlice tests cstring with an empty byte slice.
func TestCstring_EmptySlice(t *testing.T) {
	s, rest, ok := cstring([]byte{})
	if ok {
		t.Errorf("expected ok=false for empty slice, got s=%q rest=%v", s, rest)
	}
	_ = s
	_ = rest
}

// TestCstring_WithNull tests the success path of cstring.
func TestCstring_WithNull(t *testing.T) {
	b := []byte{'h', 'e', 'l', 'l', 'o', 0, 'w', 'o', 'r', 'l', 'd'}
	s, rest, ok := cstring(b)
	if !ok {
		t.Fatalf("expected ok=true, got false")
	}
	if s != "hello" {
		t.Errorf("expected s=hello, got %q", s)
	}
	if string(rest) != "world" {
		t.Errorf("expected rest=world, got %q", rest)
	}
}
