package sanitize

import "testing"

func TestWithholdResponseBody(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"failed to send to http://x: 404 Not Found (body: secret)", "failed to send to http://x: 404 Not Found (response body withheld)"},
		{"retry-able request failure: body: <html>secret</html>", "retry-able request failure: response body withheld"},
		{"dial tcp 10.0.0.7:4318: connect: connection refused", "dial tcp 10.0.0.7:4318: connect: connection refused"},
		{"", ""},
	} {
		if got := WithholdResponseBody(tc.in); got != tc.want {
			t.Errorf("WithholdResponseBody(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
