package events

import (
	"strings"
	"testing"
)

func TestEvent_TypeString_AFALG(t *testing.T) {
	e := &Event{Type: EventAFALG}
	if got := e.TypeString(); got != "CRYPTO" {
		t.Errorf("TypeString(EventAFALG) = %q, want CRYPTO", got)
	}
}

func TestEvent_FormatMessage_AFALG_AeadUnprivileged(t *testing.T) {
	e := &Event{Type: EventAFALG, Target: "aead", Details: "gcm(aes)", Bytes: 1000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "[CRYPTO]") || !strings.Contains(msg, "aead") || !strings.Contains(msg, "gcm(aes)") {
		t.Errorf("unexpected message: %q", msg)
	}
	if !strings.Contains(msg, "uid=1000") {
		t.Errorf("uid missing: %q", msg)
	}
	if !strings.Contains(msg, "Copy Fail") {
		t.Errorf("aead+unprivileged should flag the Copy Fail interface: %q", msg)
	}
}

func TestEvent_FormatMessage_AFALG_RootNotFlagged(t *testing.T) {
	e := &Event{Type: EventAFALG, Target: "aead", Details: "gcm(aes)", Bytes: 0}
	msg := e.FormatMessage()
	if strings.Contains(msg, "Copy Fail") {
		t.Errorf("root (uid 0) must not be flagged as Copy-Fail signal: %q", msg)
	}
}

func TestEvent_FormatMessage_AFALG_NonAead(t *testing.T) {
	e := &Event{Type: EventAFALG, Target: "skcipher", Details: "cbc(aes)", Bytes: 1000}
	msg := e.FormatMessage()
	if !strings.Contains(msg, "skcipher") {
		t.Errorf("unexpected message: %q", msg)
	}
	if strings.Contains(msg, "Copy Fail") {
		t.Errorf("non-aead must not be flagged: %q", msg)
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
