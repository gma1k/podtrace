package system

import "testing"

// TestCheckSELinux_DoesNotPanic exercises CheckSELinux end to end. The
// function reads hardcoded host paths and only logs (never returns), so we
// assert only that it runs to completion. With the skip env set it takes the
// not-enforcing early-return branch deterministically; without it, whichever
// host branch applies is exercised.
func TestCheckSELinux_DoesNotPanic(t *testing.T) {
	t.Run("skip-env-set-not-enforcing", func(t *testing.T) {
		t.Setenv("PODTRACE_SKIP_SELINUX_CHECK", "1")
		CheckSELinux() // selinuxEnforcing returns (false, "") -> early return
	})

	t.Run("host-state", func(t *testing.T) {
		t.Setenv("PODTRACE_SKIP_SELINUX_CHECK", "0")
		CheckSELinux() // whichever detection branch the host yields
	})
}
