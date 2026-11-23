package workloadmetrics

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestSQLOperationIsTheUppercasedLeadingKeyword(t *testing.T) {
	for _, tc := range []struct {
		statement, want string
	}{
		{"select * from t where secret = 'x'", "SELECT"},
		{"/* app=checkout */ insert into t values (1)", "INSERT"},
		{"Update", "UPDATE"},
		{"'literal'", ""},
	} {
		if got := sqlOperation(tc.statement); got != tc.want {
			t.Errorf("sqlOperation(%q) = %q, want %q", tc.statement, got, tc.want)
		}
	}
}

func TestDBOperationNameReadsWhereEachProbeWritesTheOperation(t *testing.T) {
	for _, tc := range []struct {
		event events.Event
		want  string
	}{
		{events.Event{Type: events.EventDBQuery, Target: "select * from t where secret = 'x'", Details: "ignored"}, "SELECT"},
		{events.Event{Type: events.EventDBQuery, Details: "GET"}, ""},
		{events.Event{Type: events.EventRedisCmd, Target: "ignored", Details: "HGETALL"}, "HGETALL"},
		{events.Event{Type: events.EventMemcachedCmd, Details: "set\nsecond line"}, "set"},
	} {
		if got := dbOperationName(&tc.event); got != tc.want {
			t.Errorf("dbOperationName(%v) = %q, want %q", tc.event.Type, got, tc.want)
		}
	}
}
