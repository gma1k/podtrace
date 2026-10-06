package events

import (
	"syscall"
	"testing"
)

func TestAnOpenThatFoundNoFileIsNotAnError(t *testing.T) {
	cases := []struct {
		event *Event
		want  bool
	}{
		{&Event{Type: EventOpen, Error: -int32(syscall.ENOENT)}, false},
		{&Event{Type: EventOpen}, false},
		{&Event{Type: EventOpen, Error: -int32(syscall.EACCES)}, true},
		{&Event{Type: EventOpen, Error: -int32(syscall.EMFILE)}, true},
		{&Event{Type: EventOpen, Error: -int32(syscall.EEXIST)}, true},
		{&Event{Type: EventUnlink, Error: -int32(syscall.ENOENT)}, true},
		{&Event{Type: EventRead, Error: -int32(syscall.ENOENT)}, true},
	}
	for _, c := range cases {
		if got := c.event.IsError(); got != c.want {
			t.Errorf("%v with error %d: IsError = %v, want %v", c.event.Type, c.event.Error, got, c.want)
		}
	}
}
