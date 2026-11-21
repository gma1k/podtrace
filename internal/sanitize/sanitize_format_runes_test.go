package sanitize

import "testing"

func TestInvisibleFormatRunesAreReplaced(t *testing.T) {
	for _, r := range []rune{
		0x00ad, 0x034f, 0x0600, 0x180b, 0x180e, 0x180f, 0x2060, 0x2061, 0x2064,
		0x206a, 0x206f, 0x115f, 0x1160, 0x3164, 0xffa0, 0xfff9, 0xfffb,
		0xe0001, 0xe0041, 0xe007f,
	} {
		in := "ad" + string(r) + "min"
		if got, want := Terminal(in), "ad\ufffdmin"; got != want {
			t.Errorf("Terminal(U+%04X) = %q, want %q", r, got, want)
		}
	}
}

func TestJoinersAndVariationSelectorsSurvive(t *testing.T) {
	for _, in := range []string{
		"\u2764\ufe0f",
		"\u263a\ufe0e",
		"\U0001F468\u200d\U0001F469\u200d\U0001F467",
		"\u0915\u094d\u200d\u0937",
		"\u8fbb\U000e0100",
		"m\u00fcnchen.example.de",
	} {
		if got := Terminal(in); got != in {
			t.Errorf("Terminal(%q) = %q, want unchanged", in, got)
		}
	}
}
