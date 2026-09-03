package events

import "testing"

func TestResponseStatusReadsTheFirstLineOfDetails(t *testing.T) {
	for _, tc := range []struct {
		name   string
		event  Event
		want   int
		wantOK bool
	}{
		{"plain code", Event{Details: "200"}, 200, true},
		{"code then body", Event{Details: "404\nGET /missing"}, 404, true},
		{"surrounded by space", Event{Details: "  503  \n"}, 503, true},
		{"lowest valid", Event{Details: "100"}, 100, true},
		{"highest valid", Event{Details: "599"}, 599, true},

		{"error field fallback", Event{Error: 502}, 502, true},
		{"details wins over error", Event{Details: "200", Error: 502}, 200, true},

		{"below range", Event{Details: "99"}, 0, false},
		{"above range", Event{Details: "600"}, 0, false},
		{"error below range", Event{Error: 99}, 0, false},
		{"error above range", Event{Error: 600}, 0, false},
		{"errno is not a status", Event{Error: -1}, 0, false},
		{"not a number", Event{Details: "HTTP/1.1 OK"}, 0, false},
		{"empty", Event{}, 0, false},
		{"newline only", Event{Details: "\n"}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.event.ResponseStatus()
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if got != tc.want {
				t.Errorf("code = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestResponseStatusDoesNotTreatASuccessAsAnError(t *testing.T) {
	e := Event{Type: EventHTTPResp, Details: "200"}

	code, ok := e.ResponseStatus()
	if !ok || code != 200 {
		t.Fatalf("ResponseStatus = (%d, %v), want (200, true)", code, ok)
	}
	if e.IsError() {
		t.Error("IsError reported true for a 200 response; the BPF probes normalise " +
			"Error to a failure-only value, so a success must never read as an error")
	}
}
