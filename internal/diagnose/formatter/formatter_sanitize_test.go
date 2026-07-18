package formatter

import (
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/analyzer"
)

func TestFormatter_SanitizesUntrustedNames(t *testing.T) {
	const evil = "GET /x\x1b[31m\x1b[2J\nFORGED LINE"

	outputs := []string{
		TopItems(map[string]int{evil: 3}, 5, "urls", "requests"),
		TopItemsWithRate(map[string]int{evil: 3}, 5, "urls", "requests", time.Second),
		TopTargets([]analyzer.TargetCount{{Target: evil, Count: 3}}, 5, "targets", "counts"),
	}
	for i, out := range outputs {
		if strings.ContainsRune(out, 0x1b) {
			t.Errorf("output %d leaked an ESC byte to the terminal: %q", i, out)
		}
		if strings.Contains(out, "\nFORGED LINE") {
			t.Errorf("output %d let an injected newline forge a report line: %q", i, out)
		}
	}
}
