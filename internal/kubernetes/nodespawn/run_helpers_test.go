package nodespawn

import (
	"bytes"
	"os"
	"sync"
	"testing"
)

func TestExitError_Error(t *testing.T) {
	e := &ExitError{Code: 7, Node: "node-1"}
	want := `spawn pod on node "node-1" exited with code 7`
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestPrefixedWriter_PrependsPrefixPerCompleteLine(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	w := newPrefixedWriter(&buf, "[n1] ", &mu)

	n, err := w.Write([]byte("alpha\nbeta\n"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len("alpha\nbeta\n") {
		t.Errorf("Write returned n=%d, want %d", n, len("alpha\nbeta\n"))
	}
	want := "[n1] alpha\n[n1] beta\n"
	if got := buf.String(); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestPrefixedWriter_BuffersPartialLineUntilNewline(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	w := newPrefixedWriter(&buf, "P:", &mu)

	if _, err := w.Write([]byte("hel")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("partial write should not flush, got %q", buf.String())
	}

	if _, err := w.Write([]byte("lo\n")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if got, want := buf.String(), "P:hello\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}

	if _, err := w.Write([]byte("tail")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if got, want := buf.String(), "P:hello\n"; got != want {
		t.Errorf("trailing partial must not flush, output = %q, want %q", got, want)
	}
}

func TestIndexByte(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		c    byte
		want int
	}{
		{"found-middle", []byte("abc\ndef"), '\n', 3},
		{"found-first", []byte("\nrest"), '\n', 0},
		{"not-found", []byte("abcdef"), '\n', -1},
		{"empty", []byte(""), 'x', -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := indexByte(tc.in, tc.c); got != tc.want {
				t.Errorf("indexByte(%q, %q) = %d, want %d", tc.in, tc.c, got, tc.want)
			}
		})
	}
}

func TestHostnameFromEnv(t *testing.T) {
	got := HostnameFromEnv()
	if got == "" {
		t.Errorf("HostnameFromEnv() returned empty string")
	}

	osHost, err := os.Hostname()
	if err == nil && osHost != "" && got != osHost {
		t.Errorf("HostnameFromEnv() = %q, want %q", got, osHost)
	}
}
