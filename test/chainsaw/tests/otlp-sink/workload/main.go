// Minimal OTLP/HTTP sink for e2e inspection. It accepts POST /v1/traces and
// POST /v1/metrics, logs the printable strings found in each protobuf body
// (span names, metric names and string attribute values are UTF-8 in the wire
// format), and serves a running tally at /stats.
//
// Assertions should read /stats, not the log. A PodTrace with a broad filter
// produces tens of thousands of span lines, which rotates the far rarer metric
// lines out of the window `kubectl logs` can read — a test that greps the log
// then fails for a reason that has nothing to do with the code under test.
package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
)

// printableRuns emits maximal runs of printable ASCII (>= minLen) from b, one
// per line, mimicking strings(1). This surfaces span names, metric names and
// attribute values from the OTLP protobuf without decoding it.
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

// readBody decompresses the request when the client compressed it. The OTLP
// HTTP exporters gzip by default, and a gzip stream has no printable runs at
// all, so skipping this step would make every body look empty.
func readBody(r *http.Request) ([]byte, error) {
	if r.Header.Get("Content-Encoding") != "gzip" {
		return io.ReadAll(r.Body)
	}
	reader, err := gzip.NewReader(r.Body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}

const maxRuns = 4000

type tally struct {
	mu       sync.Mutex
	Requests map[string]int
	Runs     map[string]bool
	Errors   int
}

func newTally() *tally {
	return &tally{Requests: map[string]int{}, Runs: map[string]bool{}}
}

func (t *tally) record(signal string, runs []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Requests[signal]++
	for _, run := range runs {
		if len(t.Runs) >= maxRuns {
			break
		}
		t.Runs[run] = true
	}
}

func (t *tally) failed() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Errors++
}

func (t *tally) snapshot() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	requests := map[string]int{}
	for k, v := range t.Requests {
		requests[k] = v
	}
	runs := make([]string, 0, len(t.Runs))
	for r := range t.Runs {
		runs = append(runs, r)
	}
	sort.Strings(runs)
	return map[string]any{"requests": requests, "runs": runs, "errors": t.Errors}
}

func logSignal(t *tally, signal, prefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			t.failed()
			fmt.Fprintln(os.Stderr, prefix, "read error:", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		runs := printableRuns(body, 4)
		t.record(signal, runs)
		for _, s := range runs {
			fmt.Println(prefix, s)
		}
		w.WriteHeader(http.StatusOK)
	}
}

func main() {
	t := newTally()
	http.HandleFunc("/v1/traces", logSignal(t, "traces", "OTLP:"))
	http.HandleFunc("/v1/metrics", logSignal(t, "metrics", "OTLPMETRIC:"))
	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(t.snapshot()); err != nil {
			fmt.Fprintln(os.Stderr, "stats encode error:", err)
		}
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
