package events

import "strings"

// MaxSQLKeywordLength bounds the keyword SQLKeyword accepts.
const MaxSQLKeywordLength = 32

// SQLKeyword returns a statement's leading keyword as written, after any
// whitespace, comments and opening parentheses, or "" when the statement
// does not start with one. It is all of a statement podtrace keeps: the rest
// carries the query's literals.
func SQLKeyword(statement string) string {
	rest := skipSQLPrefix(statement)
	end := 0
	for end < len(rest) && isASCIILetter(rest[end]) {
		end++
	}
	if end == 0 || end > MaxSQLKeywordLength {
		return ""
	}
	if end < len(rest) && isSQLIdentifierByte(rest[end]) {
		return ""
	}
	return rest[:end]
}

// skipSQLPrefix drops what may precede a statement's keyword.
func skipSQLPrefix(s string) string {
	for {
		trimmed := strings.TrimLeft(s, " \t\r\n(")
		switch {
		case strings.HasPrefix(trimmed, "--"):
			i := strings.IndexByte(trimmed, '\n')
			if i < 0 {
				return ""
			}
			s = trimmed[i+1:]
		case strings.HasPrefix(trimmed, "/*"):
			i := strings.Index(trimmed[2:], "*/")
			if i < 0 {
				return ""
			}
			s = trimmed[2+i+2:]
		default:
			return trimmed
		}
	}
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isSQLIdentifierByte(b byte) bool {
	return isASCIILetter(b) || (b >= '0' && b <= '9') || b == '_' || b == '$'
}
