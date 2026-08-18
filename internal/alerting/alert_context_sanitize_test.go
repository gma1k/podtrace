package alerting

import (
	"strings"
	"testing"
)

func TestSanitize_StripsControlCharsInMessageAndContext(t *testing.T) {
	a := &Alert{
		Message: "bound aead \x1b[31mEVIL\x07 transform \x00zero",
		Context: map[string]interface{}{
			"salg_name": "aead\x1b]0;pwn\x07",
			"uid":       1000,
		},
	}
	a.Sanitize()

	if strings.ContainsAny(a.Message, "\x00\x07\x1b") {
		t.Errorf("Message still carries control chars: %q", a.Message)
	}
	got, _ := a.Context["salg_name"].(string)
	if strings.ContainsAny(got, "\x07\x1b") {
		t.Errorf("Context salg_name still carries control chars: %q", got)
	}
	if a.Context["uid"] != 1000 {
		t.Errorf("non-string Context value must be preserved, got %v", a.Context["uid"])
	}
}
