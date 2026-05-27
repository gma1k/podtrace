package system

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/logger"
)

const (
	minKernelMajor = 5
	minKernelMinor = 8
)

// KernelVersion holds the parsed major.minor kernel version.
type KernelVersion struct {
	Major int
	Minor int
	Patch int
}

func (v KernelVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// AtLeast returns true if v >= other.
func (v KernelVersion) AtLeast(major, minor int) bool {
	if v.Major != major {
		return v.Major > major
	}
	return v.Minor >= minor
}

// CheckRequirements validates kernel version and BTF availability before loading
// any eBPF programs. It returns an actionable error if requirements are not met.
func CheckRequirements() error {
	kv, err := parseKernelVersion()
	if err != nil {
		// Best-effort: if we cannot parse, warn and continue rather than block.
		logger.Warn("Could not parse kernel version; proceeding anyway",
			zap.Error(err))
		return nil
	}

	if !kv.AtLeast(minKernelMajor, minKernelMinor) {
		return fmt.Errorf(
			"podtrace requires Linux kernel %d.%d+ (BPF ring buffer, BTF); "+
				"running on %s.\n\n"+
				"Upgrade the kernel or use a node image with a supported kernel.\n"+
				"  GKE/AKS/EKS: use a node pool with kernel 5.8+ (default since 2021).\n"+
				"  RHEL: enable the 5.14+ kernel via RHEL 9 or enable the latest UEK on OL8.\n"+
				"  Talos: ensure Talos ≥ v1.3 which ships kernel 6.1+",
			minKernelMajor, minKernelMinor, kv)
	}

	logger.Debug("Kernel version check passed", zap.String("kernel", kv.String()))

	if !isBTFAvailable() {
		logger.Warn(
			"Kernel BTF not found at /sys/kernel/btf/vmlinux; podtrace will attempt "+
				"to load eBPF programs without CO-RE type information.\n"+
				"  On Debian/Ubuntu: sudo apt-get install linux-image-$(uname -r)-dbgsym  (or use kernel >=5.8 from a standard repo)\n"+
				"  On RHEL/CentOS: sudo dnf install kernel-devel\n"+
				"  On Talos: BTF is built-in for all official Talos kernels; check your Talos version.\n"+
				"  Alternatively, supply a BTF file via PODTRACE_BTF_FILE=/path/to/vmlinux")
	} else {
		logger.Debug("BTF available", zap.String("path", "/sys/kernel/btf/vmlinux"))
	}

	return nil
}

// CheckSELinux checks if SELinux is in Enforcing mode and warns if so.
// It does not block execution — only the kernel can prevent BPF operations,
// and we want a clear warning before the cryptic EACCES from the kernel.
func CheckSELinux() {
	enforcing, how := selinuxEnforcing()
	if !enforcing {
		return
	}
	logger.Warn(
		"SELinux is in Enforcing mode (detected via "+how+"). "+
			"This may block eBPF attachment or cgroup reads.\n"+
			"  On OpenShift: grant the pod SCC 'privileged' or create a custom SCC "+
			"with 'allowPrivilegedContainer: true' and 'allowedCapabilities: [BPF, SYS_ADMIN]'.\n"+
			"  On RHEL/Fedora: run 'sudo setenforce 0' temporarily or add a BPF policy module:\n"+
			"    ausearch -c podtrace --raw | audit2allow -M podtrace && semodule -i podtrace.pp\n"+
			"  Set PODTRACE_SKIP_SELINUX_CHECK=1 to suppress this warning.")
}

// LockdownMode is the active level of the kernel Lockdown LSM.
type LockdownMode string

const (
	LockdownNone            LockdownMode = "none"
	LockdownIntegrity       LockdownMode = "integrity"
	LockdownConfidentiality LockdownMode = "confidentiality"
	LockdownUnknown LockdownMode = ""
)

// EnvSkipLockdownCheck is the documented escape hatch — power users on test
// kernels or anyone who has verified the check is over-triggering on their
// environment can set this to "1" to bypass.
const EnvSkipLockdownCheck = "PODTRACE_SKIP_LOCKDOWN_CHECK"

// envNodeLocal is the sentinel pod_spec.go writes into the spawn pod env.
// Inside the spawn pod it's "1"; on the workstation / --local path it's
// unset. Used here to pick the right lockdown file path without accepting
// a free-form env var (which would taint os.ReadFile and force a gosec
// G304/G703 exception).
const envNodeLocal = "PODTRACE_NODE_LOCAL"

// CheckKernelLockdown reads the kernel Lockdown LSM state and returns an
// error when the LSM is in 'confidentiality' mode, which denies all BPF
// reads of kernel RAM (helpers like bpf_probe_read_kernel{,_str} and the
// BPF_CORE_READ pointer-chase macro).
func CheckKernelLockdown() error {
	if os.Getenv(EnvSkipLockdownCheck) == "1" {
		return nil
	}

	var (
		data []byte
		err  error
	)
	if os.Getenv(envNodeLocal) == "1" {
		data, err = os.ReadFile("/host/sys/kernel/security/lockdown")
	} else {
		data, err = os.ReadFile("/sys/kernel/security/lockdown")
	}
	if err != nil {
		return nil
	}

	return evaluateLockdown(parseLockdownMode(string(data)))
}

// evaluateLockdown is the pure-function half of CheckKernelLockdown: it makes
// the block/warn/silent decision for a known LockdownMode without touching
// the filesystem so it can be unit-tested across all branches.
func evaluateLockdown(mode LockdownMode) error {
	switch mode {
	case LockdownConfidentiality:
		return fmt.Errorf(
			"kernel Lockdown LSM is in 'confidentiality' mode; BPF cannot read kernel RAM, which podtrace requires.\n" +
				"  Talos:  remove `lockdown=confidentiality` from .machine.install.extraKernelArgs, then `talosctl upgrade`\n" +
				"  Other:  boot without `lockdown=` on the kernel cmdline (or set it to `none` / `integrity`)\n" +
				"  Bypass (test/CI only): PODTRACE_SKIP_LOCKDOWN_CHECK=1")
	case LockdownIntegrity:
		logger.Warn(
			"Kernel Lockdown LSM is in 'integrity' mode; some BPF reads of kernel RAM may be restricted. " +
				"If tracing fails to load, retry with `lockdown=none` on the kernel cmdline.")
		return nil
	default:
		return nil
	}
}

// parseLockdownMode extracts the active bracketed value from the
// /sys/kernel/security/lockdown file contents.
func parseLockdownMode(s string) LockdownMode {
	lb := strings.IndexByte(s, '[')
	if lb < 0 {
		return LockdownUnknown
	}
	rb := strings.IndexByte(s[lb+1:], ']')
	if rb < 0 {
		return LockdownUnknown
	}
	active := strings.TrimSpace(s[lb+1 : lb+1+rb])
	switch LockdownMode(active) {
	case LockdownNone, LockdownIntegrity, LockdownConfidentiality:
		return LockdownMode(active)
	}
	return LockdownUnknown
}

// parseKernelVersion reads the running kernel version from /proc/version
// and returns a KernelVersion. It handles forms like:
//   - "Linux version 6.1.0-28-amd64 ..."
//   - "Linux version 5.15.0-1030-aws ..."
func parseKernelVersion() (KernelVersion, error) {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return KernelVersion{}, fmt.Errorf("read /proc/version: %w", err)
	}

	// "Linux version X.Y.Z..."
	fields := strings.Fields(string(data))
	for i, f := range fields {
		if strings.ToLower(f) == "version" && i+1 < len(fields) {
			return parseVersionString(fields[i+1])
		}
	}
	return KernelVersion{}, fmt.Errorf("could not find version field in /proc/version")
}

func parseVersionString(s string) (KernelVersion, error) {
	// Strip anything after '-' (distro suffix) or '+' (local build suffix).
	for _, sep := range []string{"-", "+"} {
		if idx := strings.Index(s, sep); idx >= 0 {
			s = s[:idx]
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return KernelVersion{}, fmt.Errorf("unexpected version string %q", s)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return KernelVersion{}, fmt.Errorf("parse major from %q: %w", s, err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return KernelVersion{}, fmt.Errorf("parse minor from %q: %w", s, err)
	}
	patch := 0
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(parts[2])
	}
	return KernelVersion{Major: major, Minor: minor, Patch: patch}, nil
}

// isBTFAvailable returns true when the kernel exposes its BTF blob.
func isBTFAvailable() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}

// selinuxEnforcing returns (true, source) when SELinux is in Enforcing mode.
func selinuxEnforcing() (bool, string) {
	if os.Getenv("PODTRACE_SKIP_SELINUX_CHECK") == "1" {
		return false, ""
	}

	// Method 1: /sys/fs/selinux/enforce contains "1" when enforcing.
	if data, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			return true, "/sys/fs/selinux/enforce"
		}
		return false, ""
	}

	// Method 2: /sys/fs/selinux exists but enforce is unreadable — still present.
	if _, err := os.Stat("/sys/fs/selinux"); err == nil {
		return true, "/sys/fs/selinux (enforce unreadable)"
	}

	// Method 3: check /proc/cmdline for selinux=1 or security=selinux.
	if data, err := os.ReadFile("/proc/cmdline"); err == nil {
		cmdline := string(data)
		if strings.Contains(cmdline, "security=selinux") || strings.Contains(cmdline, "selinux=1") {
			return true, "/proc/cmdline"
		}
	}

	return false, ""
}
