package events

import "testing"

func TestNormalizeHTTPMethodAcceptsTheConventionSet(t *testing.T) {
	for _, want := range []string{
		"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE",
	} {
		if got := NormalizeHTTPMethod(want); got != want {
			t.Errorf("NormalizeHTTPMethod(%q) = %q, want %q", want, got, want)
		}
	}
}

func TestNormalizeHTTPMethodCanonicalisesCaseAndSpace(t *testing.T) {
	for _, raw := range []string{"get", "Get", "  GET  ", "\tget\n"} {
		if got := NormalizeHTTPMethod(raw); got != "GET" {
			t.Errorf("NormalizeHTTPMethod(%q) = %q, want GET", raw, got)
		}
	}
}

func TestNormalizeHTTPMethodRejectsAnythingOutsideTheSet(t *testing.T) {
	for _, raw := range []string{
		"", "?", "FROBNICATE", "GET /etc/passwd", "GET\nX-Injected: 1",
		"gett", "G", "POST;DROP", `GET"`, "МЕТОД",
	} {
		if got := NormalizeHTTPMethod(raw); got != "" {
			t.Errorf("NormalizeHTTPMethod(%q) = %q, want empty. A `:method` pseudo-header is an "+
				"arbitrary token chosen by the peer, so anything outside the convention's set "+
				"must not reach a metric label", raw, got)
		}
	}
}

func TestNormalizeHTTPMethodBoundsCardinality(t *testing.T) {
	distinct := map[string]struct{}{}
	for i := 0; i < 5000; i++ {
		distinct[NormalizeHTTPMethod(string(rune('A'+i%26))+"OBSCURE")] = struct{}{}
	}
	if len(distinct) != 1 {
		t.Errorf("5000 unrecognised methods produced %d distinct values, want 1 (the empty "+
			"string). An unbounded label dimension is exactly what the series budget cannot "+
			"defend against, because every value is a new series", len(distinct))
	}
}

func TestEveryCodedMethodNormalisesToItself(t *testing.T) {
	for code := uint8(0); code <= 8; code++ {
		name := HTTPMethodFromCode(code)
		if name == "" {
			continue
		}
		if got := NormalizeHTTPMethod(name); got != name {
			t.Errorf("code %d renders %q which normalises to %q. The HTTP/1.x probe and the "+
				"HTTP/2 and HTTP/3 decoders must agree on the label value for the same method, "+
				"or one transport's series will not join with another's", code, name, got)
		}
	}
}
