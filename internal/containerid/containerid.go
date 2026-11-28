// Package containerid matches container IDs inside cgroup paths and
// /proc/<pid>/cgroup content.
package containerid

import "strings"

// ShortLength is the length of the abbreviated form runtimes print.
const ShortLength = 12

// InPath reports whether s names the container id. The id matches where an ID
// starts in s. Its 12-character short form, tried for a longer id, matches only
// as a whole ID: another container whose ID merely begins with the same 12
// characters names a different container.
func InPath(s, id string) bool {
	if id == "" {
		return false
	}
	if containsID(s, id, false) {
		return true
	}
	return len(id) > ShortLength && containsID(s, id[:ShortLength], true)
}

// containsID reports whether tok occurs in s at the start of an ID, and, when
// whole is set, also at its end.
func containsID(s, tok string, whole bool) bool {
	for from := 0; from <= len(s)-len(tok); {
		i := strings.Index(s[from:], tok)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(tok)
		if (start == 0 || !isIDChar(s[start-1])) && (!whole || end == len(s) || !isIDChar(s[end])) {
			return true
		}
		from = start + 1
	}
	return false
}

func isIDChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
