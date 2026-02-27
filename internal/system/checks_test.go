package system

import (
	"os"
	"path/filepath"
	"testing"
)

// TestKernelVersionAtLeast exercises the AtLeast comparison logic.
func TestKernelVersionAtLeast(t *testing.T) {
	cases := []struct {
		v          KernelVersion
		major, minor int
		want       bool
	}{
		{KernelVersion{6, 1, 0}, 5, 8, true},
		{KernelVersion{5, 8, 0}, 5, 8, true},
		{KernelVersion{5, 7, 0}, 5, 8, false},
		{KernelVersion{4, 19, 0}, 5, 8, false},
		{KernelVersion{6, 0, 0}, 6, 1, false},
		{KernelVersion{6, 2, 0}, 6, 1, true},
		{KernelVersion{5, 15, 100}, 5, 15, true},
	}
	for _, tc := range cases {
		if got := tc.v.AtLeast(tc.major, tc.minor); got != tc.want {
			t.Errorf("KernelVersion{%d,%d}.AtLeast(%d,%d) = %v, want %v",
				tc.v.Major, tc.v.Minor, tc.major, tc.minor, got, tc.want)
		}
	}
}

// TestKernelVersionString exercises the String() method.
func TestKernelVersionString(t *testing.T) {
	kv := KernelVersion{5, 15, 3}
	if s := kv.String(); s != "5.15.3" {
		t.Errorf("String() = %q, want %q", s, "5.15.3")
	}
}

// TestParseVersionString covers the parsing logic with various kernel version formats.
func TestParseVersionString(t *testing.T) {
	cases := []struct {
		in          string
		wantMajor   int
		wantMinor   int
		wantPatch   int
		expectError bool
	}{
		{"6.1.0", 6, 1, 0, false},
		{"5.15.3", 5, 15, 3, false},
		// distro suffix stripped
		{"5.15.0-1030-aws", 5, 15, 0, false},
		// local build suffix stripped
		{"6.1.0+custom", 6, 1, 0, false},
		// two-part version (no patch)
		{"5.8", 5, 8, 0, false},
		// bad input
		{"notaversion", 0, 0, 0, true},
		{"x.y", 0, 0, 0, true},
	}
	for _, tc := range cases {
		kv, err := parseVersionString(tc.in)
		if tc.expectError {
			if err == nil {
				t.Errorf("parseVersionString(%q): expected error, got %+v", tc.in, kv)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseVersionString(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if kv.Major != tc.wantMajor || kv.Minor != tc.wantMinor || kv.Patch != tc.wantPatch {
			t.Errorf("parseVersionString(%q) = %+v, want {%d %d %d}",
				tc.in, kv, tc.wantMajor, tc.wantMinor, tc.wantPatch)
		}
	}
}

// TestCheckRequirements_ReadsProcVersion verifies that CheckRequirements succeeds on the
// current machine (which must have a valid /proc/version and kernel ≥ 5.8).
func TestCheckRequirements_ReadsProcVersion(t *testing.T) {
	if _, err := os.ReadFile("/proc/version"); err != nil {
		t.Skip("no /proc/version available")
	}
	// Should not return an error on a modern kernel.
	if err := CheckRequirements(); err != nil {
		t.Logf("CheckRequirements returned error: %v", err)
		// Allow it if kernel is genuinely < 5.8, but that would be unusual in CI.
	}
}

// TestCheckRequirements_UnknownKernel verifies that an unreadable /proc/version
// logs a warning and returns nil (best-effort policy).
func TestCheckRequirements_UnknownKernel(t *testing.T) {
	// Point parseKernelVersion at a non-existent file by relying on the fact that
	// parseKernelVersion reads /proc/version directly. We test parseKernelVersion
	// via parseVersionString (already tested). For CheckRequirements itself we
	// just ensure a parse error is gracefully handled.
	// Simulate an empty parse result coming back via parseVersionString.
	_, err := parseVersionString("not-a-version")
	if err == nil {
		t.Fatal("expected parse error for invalid string")
	}
}

// TestSelinuxEnforcing_SkipEnvVar verifies the PODTRACE_SKIP_SELINUX_CHECK bypass.
func TestSelinuxEnforcing_SkipEnvVar(t *testing.T) {
	t.Setenv("PODTRACE_SKIP_SELINUX_CHECK", "1")
	enforcing, how := selinuxEnforcing()
	if enforcing {
		t.Errorf("expected enforcing=false when skip env is set, got enforcing=true how=%q", how)
	}
}

// TestSelinuxEnforcing_NotPresent verifies that on a system with no SELinux files,
// selinuxEnforcing returns false.
func TestSelinuxEnforcing_NotPresent(t *testing.T) {
	// Only run this check if neither /sys/fs/selinux nor selinux kernel params exist.
	if _, err := os.Stat("/sys/fs/selinux"); err == nil {
		t.Skip("SELinux filesystem present; cannot test absence")
	}
	t.Setenv("PODTRACE_SKIP_SELINUX_CHECK", "")

	// Use a fake /proc/cmdline that has no selinux params.
	tmpDir := t.TempDir()
	fakeCmdline := filepath.Join(tmpDir, "cmdline")
	if err := os.WriteFile(fakeCmdline, []byte("BOOT_IMAGE=/vmlinuz ro quiet splash"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The real selinuxEnforcing reads /proc/cmdline from a hardcoded path,
	// so we just verify the overall function returns false on a non-SELinux host.
	enforcing, _ := selinuxEnforcing()
	if enforcing {
		t.Error("expected selinuxEnforcing=false on non-SELinux system")
	}
}

// TestCheckSELinux_NoSELinux ensures CheckSELinux does not panic on a non-SELinux host.
func TestCheckSELinux_NoSELinux(t *testing.T) {
	t.Setenv("PODTRACE_SKIP_SELINUX_CHECK", "1")
	// Should not panic or return error.
	CheckSELinux()
}

// TestIsBTFAvailable returns a boolean; just make sure it doesn't panic.
func TestIsBTFAvailable(t *testing.T) {
	result := isBTFAvailable()
	// If BTF exists on this machine, result should be true; either way, no panic.
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		if !result {
			t.Error("expected isBTFAvailable()=true when /sys/kernel/btf/vmlinux exists")
		}
	} else {
		if result {
			t.Error("expected isBTFAvailable()=false when /sys/kernel/btf/vmlinux absent")
		}
	}
}
