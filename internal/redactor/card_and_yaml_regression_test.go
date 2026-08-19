package redactor

import (
	"strings"
	"testing"
)

func TestRedact_YAMLColonWithoutSpace(t *testing.T) {
	got := Default().RedactText("password:hunter2")
	if strings.Contains(got, "hunter2") {
		t.Errorf("password:hunter2 (no space) must be redacted, got %q", got)
	}
}

func TestRedact_CreditCardLengths(t *testing.T) {
	redacted := []string{
		"378282246310005",     // Amex, 15
		"3782 822463 10005",   // Amex grouped
		"30569309025904",      // Diners, 14
		"4111111111111111",    // Visa, 16
		"4111-1111-1111-1111", // Visa hyphenated
	}
	for _, in := range redacted {
		if got := Default().RedactText("card " + in + " end"); strings.Contains(got, in) {
			t.Errorf("card %q must be redacted, got %q", in, got)
		}
	}
}

func TestRedact_NonLuhnNumberKept(t *testing.T) {
	in := "1234567890123" // 13 digits, not Luhn-valid
	got := Default().RedactText("id " + in)
	if !strings.Contains(got, in) {
		t.Errorf("a non-Luhn numeric id must not be redacted as a card, got %q", got)
	}
}

func TestLuhnValid(t *testing.T) {
	if !luhnValid("4111111111111111") {
		t.Error("valid Visa must pass Luhn")
	}
	if !luhnValid("378282246310005") {
		t.Error("valid Amex (has a doubled digit > 9) must pass Luhn")
	}
	if luhnValid("4111111111111112") {
		t.Error("bad checksum must fail Luhn")
	}
	if luhnValid("12345678") {
		t.Error("too-short (< 13 digits) must fail")
	}
	if luhnValid("12345678901234567890") {
		t.Error("too-long (> 19 digits) must fail")
	}
}
