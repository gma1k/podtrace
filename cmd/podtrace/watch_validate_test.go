package main

import (
	"strings"
	"testing"
)

func TestDeriveWatchName_RejectsOver63Chars(t *testing.T) {
	long := strings.Repeat("a", 64)
	_, err := deriveWatchName(watchOptions{Name: long})
	if err == nil || !strings.Contains(err.Error(), "exceeds 63 characters") {
		t.Fatalf("expected a 63-character-limit error for a valid but overlong DNS name, got %v", err)
	}
}

func TestDeriveWatchName_AppNameDerivesResourceName(t *testing.T) {
	name, err := deriveWatchName(watchOptions{AppName: "Checkout"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "checkout" {
		t.Fatalf("expected lowercased app name, got %q", name)
	}
}

func TestCommonTargetValidate_InvalidNamespace(t *testing.T) {
	opts := watchOptions{
		Namespace:     "Bad_NS",
		Exporter:      "default",
		SamplePercent: -1,
	}
	_, _, _, err := commonTargetValidate(opts)
	if err == nil || !strings.Contains(err.Error(), "invalid namespace") {
		t.Fatalf("expected invalid-namespace error, got %v", err)
	}
}

func TestCommonTargetValidate_InvalidNamespaceSelector(t *testing.T) {
	opts := watchOptions{
		Namespace:         "default",
		Exporter:          "default",
		NamespaceSelector: "@@@",
		SamplePercent:     -1,
	}
	_, _, _, err := commonTargetValidate(opts)
	if err == nil || !strings.Contains(err.Error(), "invalid --namespace-selector") {
		t.Fatalf("expected invalid namespace-selector error, got %v", err)
	}
}
