package parser

import (
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestDecodeTarget_RenameRejoinsHalves(t *testing.T) {
	raw := make([]byte, maxStringLen)
	copy(raw[0:], "old.txt")
	raw[maxStringLen/2-1] = '>'
	copy(raw[maxStringLen/2:], "new.txt")

	got := decodeTarget(uint32(events.EventRename), raw)
	if got != "old.txt>new.txt" {
		t.Errorf("rename target = %q, want %q", got, "old.txt>new.txt")
	}
}

func TestDecodeTarget_RenameMissingNewName(t *testing.T) {
	raw := make([]byte, maxStringLen)
	copy(raw[0:], "only-old")
	raw[maxStringLen/2-1] = '>'
	if got := decodeTarget(uint32(events.EventRename), raw); got != "only-old" {
		t.Errorf("target = %q, want %q", got, "only-old")
	}
}

func TestDecodeTarget_NonRenameUnchanged(t *testing.T) {
	raw := make([]byte, maxStringLen)
	copy(raw[0:], "/etc/passwd")
	if got := decodeTarget(uint32(events.EventOpen), raw); got != "/etc/passwd" {
		t.Errorf("target = %q, want %q", got, "/etc/passwd")
	}
}
