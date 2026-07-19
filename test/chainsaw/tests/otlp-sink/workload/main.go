// Minimal OTLP/HTTP trace sink for e2e inspection. It accepts POST /v1/traces
// and logs the printable strings found in each protobuf body (span names and
// string attribute values are UTF-8 in the wire format), so a test can grep the
// pod logs for expected content without a full OTLP collector.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

// printableRuns emits maximal runs of printable ASCII (>= minLen) from b, one
// per line, mimicking strings(1). This surfaces span names and attribute values
// from the OTLP protobuf without decoding it.
func printableRuns(b []byte, minLen int) []string {
	var out []string
	start := -1
	for i := 0; i <= len(b); i++ {
		printable := i < len(b) && b[i] >= 0x20 && b[i] < 0x7f
		if printable {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if i-start >= minLen {
				out = append(out, string(b[start:i]))
			}
			start = -1
		}
	}
	return out
}

func main() {
	http.HandleFunc("/v1/traces", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		for _, s := range printableRuns(body, 4) {
			fmt.Println("OTLP:", s)
		}
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	addr := ":4318"
	fmt.Fprintln(os.Stderr, "otlp-sink listening on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		os.Exit(1)
	}
}
