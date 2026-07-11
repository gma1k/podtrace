package events

import (
	"testing"
)

func TestEvent_TypeString_AFALG(t *testing.T) {
	e := &Event{Type: EventAFALG}
	if got := e.TypeString(); got != "CRYPTO" {
		t.Errorf("TypeString(EventAFALG) = %q, want CRYPTO", got)
	}
}

func TestEvent_IsCopyFailSignal(t *testing.T) {
	cases := []struct {
		name string
		ev   Event
		want bool
	}{
		{"aead unprivileged", Event{Type: EventAFALG, Target: "aead", Bytes: 1000}, true},
		{"aead root", Event{Type: EventAFALG, Target: "aead", Bytes: 0}, false},
		{"skcipher unprivileged", Event{Type: EventAFALG, Target: "skcipher", Bytes: 1000}, false},
		{"wrong type", Event{Type: EventConnect, Target: "aead", Bytes: 1000}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.ev.IsCopyFailSignal(); got != c.want {
				t.Errorf("IsCopyFailSignal() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestEventAFALG_WireValue(t *testing.T) {
	if EventAFALG != 39 {
		t.Errorf("EventAFALG = %d, want 39 (must match EVENT_AF_ALG in bpf/events.h)", EventAFALG)
	}
}
