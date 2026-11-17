package quicinitial

import "testing"

func TestALPNNamesAfterTheDeclaredListAreIgnored(t *testing.T) {
	body := []byte{0x00, 0x03, 0x02, 'h', '2', 0x02, 'h', '3'}
	if got := parseALPNExtension(body); len(got) != 1 || got[0] != "h2" {
		t.Errorf("got %v, want only the name inside the declared list, [h2]", got)
	}
	if got := parseALPNExtension([]byte{0x00, 0x00, 0x02, 'h', '3'}); got != nil {
		t.Errorf("an empty declared list yielded %v", got)
	}
}
