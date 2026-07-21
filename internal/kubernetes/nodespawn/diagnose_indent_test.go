package nodespawn

import (
	"strings"
	"testing"
)

func TestAttachFailedError_NilReceiver(t *testing.T) {
	var e *AttachFailedError
	if got := e.Error(); got != "<nil>" {
		t.Errorf("nil *AttachFailedError.Error() = %q, want %q", got, "<nil>")
	}
}

func TestIndent_EmptyStringReturnsEmpty(t *testing.T) {
	if got := indent("", "    "); got != "" {
		t.Errorf("indent(\"\") = %q, want empty", got)
	}
}

func TestIndent_PrefixesEveryLineAndTrimsTrailingNewline(t *testing.T) {
	got := indent("line-one\nline-two\n", "  ")
	want := "  line-one\n  line-two"
	if got != want {
		t.Errorf("indent = %q, want %q", got, want)
	}

	if strings.HasSuffix(got, "  ") {
		t.Errorf("indent left a dangling prefixed empty line: %q", got)
	}
}
