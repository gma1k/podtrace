package events

import "testing"

func TestOnlyNoRouteForTheAddressFamilyIsUnreachable(t *testing.T) {
	for errno, want := range map[int32]bool{
		-101: true, 101: true,
		-97: true, 97: true,
		-111: false,
		-110: false,
		-113: false,
		-99:  false,
		0:    false,
	} {
		if got := IsAddressFamilyUnreachable(errno); got != want {
			t.Errorf("IsAddressFamilyUnreachable(%d) = %v, want %v", errno, got, want)
		}
	}
}

func TestOnlyASynchronousConnectCanBeUnreachable(t *testing.T) {
	if !IsUnreachableConnect(&Event{Type: EventConnect, Error: -101}) {
		t.Error("an ENETUNREACH connect() was not recognised")
	}
	if IsUnreachableConnect(&Event{Type: EventConnectResult, Error: -101}) {
		t.Error("a handshake result was treated as unreachable; its SYN was already sent")
	}
	if IsUnreachableConnect(&Event{Type: EventTCPSend, Error: -101}) {
		t.Error("a send failure was treated as an unreachable connect")
	}
	if IsUnreachableConnect(nil) {
		t.Error("nil was treated as an unreachable connect")
	}
}
