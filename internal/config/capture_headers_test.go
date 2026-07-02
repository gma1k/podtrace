package config

import (
	"reflect"
	"testing"
)

func TestParseCaptureHeaders(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", "", nil},
		{"single", "Content-Type", []string{"content-type"}},
		{"trims and lowercases", " X-Request-Id , content-type ", []string{"x-request-id", "content-type"}},
		{"drops invalid tokens", "good,-also-good-,bad name,tab\theader", []string{"good", "-also-good-"}},
		{"caps at MaxCaptureHeaders", "a,b,c,d,e,f", []string{"a", "b", "c", "d"}},
		{"drops overlong names", "this-header-name-is-far-too-long-to-capture,ok", []string{"ok"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseCaptureHeaders(tc.raw); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseCaptureHeaders(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}
