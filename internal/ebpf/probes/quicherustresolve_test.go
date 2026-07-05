package probes

import "testing"

func TestQuicheRustSendRequestPattern(t *testing.T) {
	matches := []string{
		"_ZN6quiche2h310Connection12send_request17h8165242841e11bc4E",
		"_RNvMs2_NtCs4fqI2P2rA04_6quiche2h3NtB5_10Connection12send_request",
	}
	for _, name := range matches {
		if !nameContainsAll(name, quicheRustSendRequestPattern...) {
			t.Errorf("pattern did not match %q", name)
		}
	}

	rejects := []string{
		"_ZN6quiche2h310Connection13send_response17h1111111111111111E",
		"_ZN6quiche2h310Connection4poll17h2222222222222222E",
		"_ZN6quiche2h310Connection14send_additional17h3333333333333333E",
		"_ZN2h26client13SendRequest12send_request17h4444444444444444E",
		"_ZN6quiche10Connection11stream_send17h5555555555555555E",
	}
	for _, name := range rejects {
		if nameContainsAll(name, quicheRustSendRequestPattern...) {
			t.Errorf("pattern wrongly matched %q", name)
		}
	}
}