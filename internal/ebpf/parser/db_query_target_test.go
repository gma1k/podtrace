package parser

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func rawTarget(s string) []byte {
	raw := make([]byte, maxStringLen)
	copy(raw, s)
	return raw
}

func TestADBQueryTargetKeepsOnlyTheStatementKeyword(t *testing.T) {
	for _, tc := range []struct {
		statement, want string
	}{
		{"INSERT INTO orders VALUES (42, 'secret-user@example.com')", "INSERT"},
		{"/* app=checkout */ select count(*) from orders where email = 'secret-user@example.com'", "select"},
		{"\n    UPDATE orders\n    SET id = 43", "UPDATE"},
		{"-- " + strings.Repeat("x", 200), ""},
		{"'secret-user@example.com'", ""},
	} {
		got := decodeTarget(uint32(events.EventDBQuery), rawTarget(tc.statement))
		if got != tc.want {
			t.Errorf("decodeTarget(%q) = %q, want %q", tc.statement, got, tc.want)
		}
		if strings.Contains(got, "secret") {
			t.Errorf("a query literal reached the event target: %q", got)
		}
	}
}

func TestOtherTargetsAreNotReducedToAKeyword(t *testing.T) {
	if got := decodeTarget(uint32(events.EventOpen), rawTarget("/var/lib/app data.db")); got != "/var/lib/app data.db" {
		t.Errorf("decodeTarget(open) = %q", got)
	}
}
