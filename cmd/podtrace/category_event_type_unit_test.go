package main

import "testing"

func TestCategoryForEventType_AllBranches(t *testing.T) {
	cases := map[string]string{
		"dns":     "dns",
		"DNS":     "dns",
		"net":     "net",
		"NET":     "net",
		"fs":      "fs",
		"cpu":     "cpu",
		"proc":    "proc",
		"unknown": "",
		"":        "",
	}
	for in, want := range cases {
		if got := categoryForEventType(in); got != want {
			t.Errorf("categoryForEventType(%q) = %q, want %q", in, got, want)
		}
	}
}
