package events

import (
	"strings"
	"testing"
)

func TestSQLKeywordTakesOnlyTheLeadingKeyword(t *testing.T) {
	for _, tc := range []struct {
		statement, want string
	}{
		{"SELECT id FROM users WHERE email = 'a@b.c'", "SELECT"},
		{"select 1", "select"},
		{"  \n\tinsert into t values (1)", "insert"},
		{"\n    SELECT *\n    FROM orders", "SELECT"},
		{"(SELECT 1) UNION (SELECT 2)", "SELECT"},
		{"-- fetch the user\nUPDATE users SET name = 'x'", "UPDATE"},
		{"/* app=checkout */ DELETE FROM carts", "DELETE"},
		{"/* a */ -- b\n /* c */ WITH x AS (SELECT 1) SELECT * FROM x", "WITH"},
		{"BEGIN", "BEGIN"},
		{"commit;", "commit"},
		{"VACUUM(ANALYZE)", "VACUUM"},
		{"", ""},
		{"   ", ""},
		{"-- only a comment", ""},
		{"/* unterminated", ""},
		{"'quoted literal'", ""},
		{"[redacted]", ""},
		{"123 SELECT", ""},
		{"select_users()", ""},
		{"SELECT1", ""},
		{"$1", ""},
		{"ÄNDERE", ""},
		{strings.Repeat("A", MaxSQLKeywordLength), strings.Repeat("A", MaxSQLKeywordLength)},
		{strings.Repeat("A", MaxSQLKeywordLength+1), ""},
	} {
		if got := SQLKeyword(tc.statement); got != tc.want {
			t.Errorf("SQLKeyword(%q) = %q, want %q", tc.statement, got, tc.want)
		}
	}
}
