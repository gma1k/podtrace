package events

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

func TestHTTPMethodCodesMatchBPF(t *testing.T) {
	src, err := os.ReadFile("../../bpf/http.c")
	if err != nil {
		t.Fatalf("read bpf/http.c: %v", err)
	}

	re := regexp.MustCompile(`(?m)^#define HTTP_METHOD_(\w+)\s+(\d+)$`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatal("no HTTP_METHOD_* defines found in bpf/http.c; this test guards the " +
			"wire contract between the probe and the parser and would pass vacuously")
	}

	want := map[string]string{
		"UNKNOWN": "",
		"GET":     "GET",
		"PUT":     "PUT",
		"POST":    "POST",
		"HEAD":    "HEAD",
		"PATCH":   "PATCH",
		"DELETE":  "DELETE",
		"OPTIONS": "OPTIONS",
	}

	seen := map[string]bool{}
	for _, m := range matches {
		name, rawCode := m[1], m[2]
		code, err := strconv.Atoi(rawCode)
		if err != nil {
			t.Fatalf("HTTP_METHOD_%s has non-numeric value %q", name, rawCode)
		}
		seen[name] = true

		expected, known := want[name]
		if !known {
			t.Errorf("bpf/http.c defines HTTP_METHOD_%s, which HTTPMethodFromCode does "+
				"not handle; a probe emitting it would decode as an unknown method", name)
			continue
		}
		if got := HTTPMethodFromCode(uint8(code)); got != expected {
			t.Errorf("HTTPMethodFromCode(%d) = %q, but bpf/http.c calls %d "+
				"HTTP_METHOD_%s, so the probe and parser disagree", code, got, code, name)
		}
	}

	for name := range want {
		if !seen[name] {
			t.Errorf("HTTPMethodFromCode handles %s but bpf/http.c no longer defines "+
				"HTTP_METHOD_%s", name, name)
		}
	}
}

func TestHTTPMethodFromCodeRejectsUnknownCodes(t *testing.T) {
	for _, code := range []uint8{0, 8, 9, 42, 255} {
		if got := HTTPMethodFromCode(code); got != "" {
			t.Errorf("HTTPMethodFromCode(%d) = %q, want empty; an unrecognised code must "+
				"not become a fabricated method name", code, got)
		}
	}
}

func TestHTTPMethodCodesAreDistinct(t *testing.T) {
	seen := map[string]uint8{}
	for code := uint8(1); code <= 7; code++ {
		name := HTTPMethodFromCode(code)
		if name == "" {
			t.Errorf("code %d maps to nothing but is inside the assigned range", code)
			continue
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("codes %d and %d both map to %q", prev, code, name)
		}
		seen[name] = code
	}
	if len(seen) != 7 {
		t.Errorf("got %d distinct methods, want 7", len(seen))
	}
}
