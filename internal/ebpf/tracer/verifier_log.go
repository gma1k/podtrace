package tracer

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/logger"
)

const (
	envBPFLogLevel = "PODTRACE_BPF_LOG_LEVEL"
	envBPFLogSize  = "PODTRACE_BPF_LOG_SIZE"

	defaultVerboseLogSize uint32 = 64 * 1024
)

// applyVerifierLogOptions reads PODTRACE_BPF_LOG_LEVEL / PODTRACE_BPF_LOG_SIZE
// and applies them to opts.Programs.LogLevel / opts.Programs.LogSizeStart.
func applyVerifierLogOptions(opts *ebpf.CollectionOptions) {
	level := parseBPFLogLevel(os.Getenv(envBPFLogLevel))
	if level == 0 {
		return
	}
	opts.Programs.LogLevel = level
	opts.Programs.LogSizeStart = parseBPFLogSize(os.Getenv(envBPFLogSize))
	logger.Debug("Verifier log capture enabled",
		zap.String(envBPFLogLevel, os.Getenv(envBPFLogLevel)),
		zap.Uint32("log_size_start", opts.Programs.LogSizeStart),
	)
}

// parseBPFLogLevel turns the value of PODTRACE_BPF_LOG_LEVEL into a bitmask of
// cilium/ebpf LogLevel constants. Unknown / empty values return 0, which
// signals "use the library default (no upfront log, fallback retry on error)".
//
// Accepted forms (case-insensitive, whitespace-trimmed):
//
//	"" / "disabled" / "none" / "0" / "false"  → 0
//	"branch" / "1"                            → LogLevelBranch
//	"stats" / "2"                             → LogLevelStats
//	"instructions" / "instruction" / "verbose" / "all" / "3"
//	                                          → LogLevelBranch | LogLevelInstruction | LogLevelStats
func parseBPFLogLevel(s string) ebpf.LogLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "disabled", "none", "0", "false":
		return 0
	case "branch", "1":
		return ebpf.LogLevelBranch
	case "stats", "2":
		return ebpf.LogLevelStats
	case "instructions", "instruction", "verbose", "all", "3":
		return ebpf.LogLevelBranch | ebpf.LogLevelInstruction | ebpf.LogLevelStats
	}
	return 0
}

// parseBPFLogSize parses PODTRACE_BPF_LOG_SIZE. Empty / unparseable / zero
// returns the default (defaultVerboseLogSize). uint32 ceiling is the cilium/ebpf
// API limit (LogSizeStart is uint32).
func parseBPFLogSize(s string) uint32 {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultVerboseLogSize
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 {
		return defaultVerboseLogSize
	}
	return uint32(n)
}

// logVerifierFailure surfaces the full kernel verifier output when an eBPF
// load fails.
func logVerifierFailure(err error) {
	if err == nil {
		return
	}
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		return
	}
	logger.Error(
		"eBPF program load rejected by the kernel verifier — full log follows",
		zap.String("verifier_output", fmt.Sprintf("%+v", ve)),
	)
}