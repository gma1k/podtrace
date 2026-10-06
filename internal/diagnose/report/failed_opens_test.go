package report

import (
	"strings"
	"syscall"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestAFailedOpenIsNotADescriptorLeak(t *testing.T) {
	enoent := -int32(syscall.ENOENT)
	evts := []*events.Event{
		{Type: events.EventOpen, Target: "/lib/glibc-hwcaps/x86-64-v3/libm.so.6", Error: enoent},
		{Type: events.EventOpen, Target: "/lib/glibc-hwcaps/x86-64-v2/libm.so.6", Error: enoent},
		{Type: events.EventOpen, Target: "/lib/libm.so.6"},
		{Type: events.EventClose},
	}
	if got := formatFileDescriptorLeak(evts[:3], evts[3:]); got != "" {
		t.Errorf("got %q for one successful open and its close", got)
	}
}

func TestMoreSuccessfulOpensThanClosesIsALeak(t *testing.T) {
	evts := []*events.Event{
		{Type: events.EventOpen, Target: "/data/a"},
		{Type: events.EventOpen, Target: "/data/b"},
		{Type: events.EventOpen, Target: "/data/c", Error: -int32(syscall.EACCES)},
	}
	got := formatFileDescriptorLeak(evts, []*events.Event{{Type: events.EventClose}})
	if !strings.Contains(got, "1 more opens than closes") {
		t.Errorf("got %q, want one leaked descriptor", got)
	}
}

func TestTheTopOpenedFilesAreFilesThatWereOpened(t *testing.T) {
	evts := []*events.Event{
		{Type: events.EventOpen, Target: "/etc/ld.so.cache", Error: -int32(syscall.ENOENT)},
		{Type: events.EventOpen, Target: "/etc/ld.so.cache", Error: -int32(syscall.ENOENT)},
		{Type: events.EventOpen, Target: "/lib/libm.so.6"},
	}
	got := buildFileCounts(evts)
	if len(got) != 1 || got["/lib/libm.so.6"] != 1 {
		t.Errorf("got %v, want only the file that opened", got)
	}
}
