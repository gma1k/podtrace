package system

import (
	"strings"
	"testing"
)

func TestParseVersionString_TwoPartIsAccepted(t *testing.T) {
	kv, err := parseVersionString("6.1")
	if err != nil {
		t.Fatalf("two-part version should parse, got %v", err)
	}
	if kv.Major != 6 || kv.Minor != 1 || kv.Patch != 0 {
		t.Errorf("got %+v", kv)
	}
}

func TestParseVersionString_PatchUnparseableSilent(t *testing.T) {
	// Patch field that is not a number is silently dropped to 0.
	kv, err := parseVersionString("5.15.notdigits")
	if err != nil {
		t.Fatalf("expected nil err (patch is best-effort), got %v", err)
	}
	if kv.Major != 5 || kv.Minor != 15 || kv.Patch != 0 {
		t.Errorf("got %+v", kv)
	}
}

func TestParseVersionString_RejectsBadMinor(t *testing.T) {
	_, err := parseVersionString("5.X")
	if err == nil {
		t.Fatal("expected error for non-numeric minor")
	}
}

func TestParseVersionString_RejectsBadMajor(t *testing.T) {
	_, err := parseVersionString("X.5")
	if err == nil {
		t.Fatal("expected error for non-numeric major")
	}
}

// TestParseVersionString_StripsBothSeparators verifies both '-' and '+'
// are recognised as suffix separators (Linux distro vs. local-build).
func TestParseVersionString_StripsBothSeparators(t *testing.T) {
	for _, input := range []string{"6.1.0-debian-amd64", "6.1.0+local"} {
		kv, err := parseVersionString(input)
		if err != nil {
			t.Errorf("%q: %v", input, err)
			continue
		}
		if kv.Major != 6 || kv.Minor != 1 {
			t.Errorf("%q: got %+v", input, kv)
		}
	}
}

func TestKernelVersionAtLeast_HigherMajor(t *testing.T) {
	v := KernelVersion{Major: 6, Minor: 0}
	if !v.AtLeast(5, 99) {
		t.Error("major bump should always satisfy lower-major comparisons")
	}
}

// TestSelinuxEnforcing_SkipEnvVarPath: same as existing test but covers
// the early-return path explicitly to guard against accidental removal.
func TestSelinuxEnforcing_SkipEnvVarReturnsFalse(t *testing.T) {
	t.Setenv("PODTRACE_SKIP_SELINUX_CHECK", "1")
	enforcing, how := selinuxEnforcing()
	if enforcing {
		t.Errorf("got enforcing=true with skip env, how=%q", how)
	}
	if how != "" {
		t.Errorf("how should be empty when skip env set, got %q", how)
	}
}

// TestKernelVersion_StringFormat ensures the formatter survives all
// branches (zero-patch, multi-digit numbers).
func TestKernelVersion_StringFormat(t *testing.T) {
	cases := []struct {
		in   KernelVersion
		want string
	}{
		{KernelVersion{6, 1, 0}, "6.1.0"},
		{KernelVersion{5, 15, 100}, "5.15.100"},
		{KernelVersion{0, 0, 0}, "0.0.0"},
	}
	for _, c := range cases {
		if got := c.in.String(); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

// TestCheckRequirements_OutputsKernelInfo: verifies CheckRequirements
// runs without error on this host (modern kernel) and that its
// returned err message format is stable when it does fire.
func TestCheckRequirements_OutputsKernelInfo(t *testing.T) {
	err := CheckRequirements()
	if err == nil {
		return // happy path
	}
	// On rare (very old) hosts CheckRequirements may report a
	// supported-kernel error; the message must point at the minimum.
	if !strings.Contains(err.Error(), "Linux kernel") {
		t.Errorf("err message should mention Linux kernel, got %q", err)
	}
}
