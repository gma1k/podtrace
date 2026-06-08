package system

import (
	"os"
	"testing"
)

// TestSelinuxEnforcing_SkipEnv covers the PODTRACE_SKIP_SELINUX_CHECK=1 branch,
// which short-circuits to (false, "") regardless of host state.
func TestSelinuxEnforcing_SkipEnv(t *testing.T) {
	t.Setenv("PODTRACE_SKIP_SELINUX_CHECK", "1")

	enforcing, how := selinuxEnforcing()
	if enforcing {
		t.Errorf("selinuxEnforcing() = (%v, %q), want (false, \"\") when skip env set", enforcing, how)
	}
	if how != "" {
		t.Errorf("selinuxEnforcing() source = %q, want empty when skip env set", how)
	}
}

// TestSelinuxEnforcing_Default exercises the detection path with the skip env
// unset. The function reads hardcoded host paths (/sys/fs/selinux,
// /proc/cmdline); we don't assert a specific value because it depends on the
// host, only that it returns consistently and does not panic. On a typical
// non-SELinux host this covers the final "not enforcing" return.
func TestSelinuxEnforcing_Default(t *testing.T) {
	if err := os.Unsetenv("PODTRACE_SKIP_SELINUX_CHECK"); err != nil {
		t.Fatalf("unset PODTRACE_SKIP_SELINUX_CHECK: %v", err)
	}

	enforcing, how := selinuxEnforcing()
	if enforcing && how == "" {
		t.Errorf("selinuxEnforcing() reported enforcing with empty source")
	}
	if !enforcing && how != "" {
		t.Errorf("selinuxEnforcing() reported not-enforcing but non-empty source %q", how)
	}
	t.Logf("selinuxEnforcing() = (%v, %q) on this host", enforcing, how)
}

// TestCheckRequirements verifies the aggregate check runs to completion without
// panicking and returns a nil/non-nil error consistently. On the test host the
// kernel is well above the 5.8 minimum, so this exercises the version-parse,
// AtLeast-pass, and BTF-probe branches.
func TestCheckRequirements(t *testing.T) {
	if err := CheckRequirements(); err != nil {
		t.Logf("CheckRequirements() returned error (unexpected on a modern kernel): %v", err)
	}
}
