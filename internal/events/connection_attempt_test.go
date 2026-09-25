package events

import "testing"

func TestEachConnectionAttemptIsScoredExactlyOnce(t *testing.T) {
	for _, tc := range []struct {
		name   string
		typ    EventType
		failed bool
		want   bool
	}{
		{"a connect that queued its SYN only starts the attempt", EventConnect, false, false},
		{"a connect that failed synchronously is the attempt", EventConnect, true, true},
		{"an established handshake is the attempt", EventConnectResult, false, true},
		{"a refused handshake is the attempt", EventConnectResult, true, true},
		{"other network events are not attempts", EventTCPSend, true, false},
	} {
		if got := CountsAsConnectionAttempt(tc.typ, tc.failed); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAConnectResultIsANetworkEvent(t *testing.T) {
	e := &Event{Type: EventConnectResult, Error: -111}
	if got := e.TypeString(); got != "NET" {
		t.Errorf("TypeString = %q, want NET", got)
	}
	if !e.IsError() {
		t.Error("a refused handshake did not read as an error")
	}
}
