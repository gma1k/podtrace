// Package sanitize scrubs attacker-influenced strings before they are
// rendered into human-facing text (diagnose reports) that an operator may
// view in a terminal.
package sanitize

import "strings"

const Replacement = '�'

// Terminal returns s with every terminal-unsafe rune replaced by
// Replacement.
func Terminal(s string) string {
	if strings.IndexFunc(s, unsafeRune) < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unsafeRune(r) {
			b.WriteRune(Replacement)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// unsafeRune reports whether r can manipulate a terminal or forge report
// structure when printed:
//
//   - C0 controls (0x00–0x1f): includes ESC (starts ANSI sequences) and
//     TAB/CR/LF (would forge report columns and lines);
//   - DEL (0x7f) and the C1 controls (0x80–0x9f);
//   - the Unicode line/paragraph separators (U+2028/U+2029);
//   - the bidirectional override and isolate format characters
//     (U+202A–U+202E, U+2066–U+2069) — the Trojan-Source spoofing class.
//
// Every other rune, including normal printable Unicode, is preserved.
func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f:
		return true
	case r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x2028, r == 0x2029:
		return true
	case r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	default:
		return false
	}
}
