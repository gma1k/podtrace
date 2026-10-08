package analyzer

import (
	"fmt"

	"github.com/gma1k/podtrace/internal/events"
)

// TLSFailingProcesses counts the failed TLS handshakes by the program that
// made them, so a report can say which client cannot connect.
func TLSFailingProcesses(handshakes []*events.Event) map[string]int {
	out := map[string]int{}
	for _, e := range handshakes {
		if e == nil || e.Error == 0 {
			continue
		}
		if e.ProcessName != "" {
			out[e.ProcessName]++
		} else {
			out[fmt.Sprintf("pid %d", e.PID)]++
		}
	}
	return out
}
