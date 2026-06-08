package procfs

import (
	"strings"
	"testing"
)

func TestStat_RootOpenFails(t *testing.T) {
	withProcBase(t, "/no/such/proc/base")
	_, err := Stat("self/stat")
	if err == nil {
		t.Fatal("expected error when root cannot be opened")
	}
	if !strings.Contains(err.Error(), "procfs") {
		t.Errorf("error should be wrapped with procfs prefix, got %v", err)
	}
}

func TestStat_MissingRelative(t *testing.T) {
	withProcBase(t, t.TempDir())
	if _, err := Stat("does-not-exist"); err == nil {
		t.Fatal("expected error for missing relative path")
	}
}

func TestOpen_RootOpenFails(t *testing.T) {
	withProcBase(t, "/no/such/proc/base")
	_, err := Open("self/maps")
	if err == nil {
		t.Fatal("expected error when root cannot be opened")
	}
	if !strings.Contains(err.Error(), "procfs") {
		t.Errorf("error should be wrapped with procfs prefix, got %v", err)
	}
}

func TestOpen_MissingRelative(t *testing.T) {
	withProcBase(t, t.TempDir())
	if _, err := Open("does-not-exist"); err == nil {
		t.Fatal("expected error for missing relative path")
	}
}
