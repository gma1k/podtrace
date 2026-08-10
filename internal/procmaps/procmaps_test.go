package procmaps

import (
	"testing"
)

func TestParseLine_PathWithSpaceIsNotTruncated(t *testing.T) {
	line := "7f7da821b000-7f7da821c000 r--p 00000000 00:2c 860                        /usr/lib/x86_64-linux-gnu/libssl.so.3 X"

	e, ok := ParseLine(line)
	if !ok {
		t.Fatal("ParseLine rejected a valid line")
	}
	want := "/usr/lib/x86_64-linux-gnu/libssl.so.3 X"
	if e.Path != want {
		t.Fatalf("path = %q, want %q", e.Path, want)
	}
	if e.AddrRange != "7f7da821b000-7f7da821c000" {
		t.Errorf("addrRange = %q", e.AddrRange)
	}
	if e.Perms != "r--p" {
		t.Errorf("perms = %q", e.Perms)
	}
}

func TestParseLine_MultipleSpacesInPath(t *testing.T) {
	line := "7f00-7f01 r-xp 00000000 08:01 12 /opt/a b/c  d/libssl.so.3"

	e, ok := ParseLine(line)
	if !ok {
		t.Fatal("ParseLine rejected a valid line")
	}
	if e.Path != "/opt/a b/c  d/libssl.so.3" {
		t.Fatalf("path = %q", e.Path)
	}
}

func TestParseLine_Deleted(t *testing.T) {
	line := "7f00-7f01 r-xp 00000000 08:01 12 /tmp/libnetty_tcnative.so (deleted)"

	e, ok := ParseLine(line)
	if !ok {
		t.Fatal("ParseLine rejected a valid line")
	}
	if !e.Deleted {
		t.Error("deleted = false, want true")
	}
	if e.Path != "/tmp/libnetty_tcnative.so" {
		t.Errorf("path = %q", e.Path)
	}
}

func TestParseLine_Anonymous(t *testing.T) {
	e, ok := ParseLine("7f00-7f01 rw-p 00000000 00:00 0")
	if !ok {
		t.Fatal("ParseLine rejected an anonymous mapping")
	}
	if e.Path != "" {
		t.Errorf("path = %q, want empty", e.Path)
	}
	if e.Named() {
		t.Error("Named() = true for an anonymous mapping")
	}
}

func TestParseLine_PseudoMapping(t *testing.T) {
	e, ok := ParseLine("7ffd000-7ffe000 rw-p 00000000 00:00 0                     [stack]")
	if !ok {
		t.Fatal("ParseLine rejected a pseudo mapping")
	}
	if e.Named() {
		t.Error("Named() = true for [stack]")
	}
}

func TestParseLine_Executable(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"7f00-7f01 r-xp 00000000 08:01 12 /lib/libssl.so.3", true},
		{"7f00-7f01 r--p 00000000 08:01 12 /lib/libssl.so.3", false},
		{"7f00-7f01 rwxp 00000000 08:01 12 /lib/libssl.so.3", true},
	}
	for _, c := range cases {
		e, ok := ParseLine(c.line)
		if !ok {
			t.Fatalf("ParseLine rejected %q", c.line)
		}
		if e.Executable() != c.want {
			t.Errorf("Executable() = %v for %q, want %v", e.Executable(), c.line, c.want)
		}
	}
}

func TestParseLine_Malformed(t *testing.T) {
	for _, line := range []string{
		"",
		"   ",
		"7f00-7f01",
		"7f00-7f01 r-xp",
		"7f00-7f01 r-xp 00000000 08:01",
		"not-an-address r-xp 00000000 08:01 12 /lib/libssl.so.3",
	} {
		if _, ok := ParseLine(line); ok {
			t.Errorf("ParseLine accepted malformed line %q", line)
		}
	}
}

func TestParseLine_TabSeparated(t *testing.T) {
	e, ok := ParseLine("7f00-7f01\tr-xp\t00000000\t08:01\t12\t/lib/libssl.so.3")
	if !ok {
		t.Fatal("ParseLine rejected a tab-separated line")
	}
	if e.Path != "/lib/libssl.so.3" {
		t.Errorf("path = %q", e.Path)
	}
}
