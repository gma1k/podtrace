package tracer

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestParseBPFLogLevel(t *testing.T) {
	verbose := ebpf.LogLevelBranch | ebpf.LogLevelInstruction | ebpf.LogLevelStats

	tests := []struct {
		name string
		in   string
		want ebpf.LogLevel
	}{
		{"empty is disabled (library default applies)", "", 0},
		{"disabled keyword", "disabled", 0},
		{"none keyword", "none", 0},
		{"zero numeric", "0", 0},
		{"false keyword", "false", 0},
		{"branch keyword", "branch", ebpf.LogLevelBranch},
		{"branch numeric", "1", ebpf.LogLevelBranch},
		{"stats keyword", "stats", ebpf.LogLevelStats},
		{"stats numeric", "2", ebpf.LogLevelStats},
		{"instructions keyword", "instructions", verbose},
		{"instruction singular keyword", "instruction", verbose},
		{"verbose keyword", "verbose", verbose},
		{"all keyword", "all", verbose},
		{"instructions numeric", "3", verbose},
		{"whitespace trimmed", "  verbose  ", verbose},
		{"case-insensitive", "VERBOSE", verbose},
		{"unknown value falls back to disabled (no surprise behaviour on typo)", "moarlogs", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseBPFLogLevel(tc.in); got != tc.want {
				t.Errorf("parseBPFLogLevel(%q) = %#x, want %#x", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseBPFLogSize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want uint32
	}{
		{"empty returns default 64 KiB", "", defaultVerboseLogSize},
		{"unparseable returns default", "huge", defaultVerboseLogSize},
		{"zero returns default (no point allocating 0)", "0", defaultVerboseLogSize},
		{"explicit value honoured", "131072", 131072},
		{"whitespace trimmed", "  131072  ", 131072},
		{"negative returns default (unparseable as uint)", "-1", defaultVerboseLogSize},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseBPFLogSize(tc.in); got != tc.want {
				t.Errorf("parseBPFLogSize(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestApplyVerifierLogOptions_DisabledByDefault(t *testing.T) {
	t.Setenv(envBPFLogLevel, "")
	var opts ebpf.CollectionOptions
	applyVerifierLogOptions(&opts)

	if opts.Programs.LogLevel != 0 {
		t.Errorf("default LogLevel should be 0, got %#x", opts.Programs.LogLevel)
	}
	if opts.Programs.LogSizeStart != 0 {
		t.Errorf("default LogSizeStart should be 0 (cilium/ebpf default kicks in), got %d", opts.Programs.LogSizeStart)
	}
}

func TestApplyVerifierLogOptions_VerboseSetsBothFields(t *testing.T) {
	t.Setenv(envBPFLogLevel, "verbose")
	t.Setenv(envBPFLogSize, "")
	var opts ebpf.CollectionOptions
	applyVerifierLogOptions(&opts)

	wantLevel := ebpf.LogLevelBranch | ebpf.LogLevelInstruction | ebpf.LogLevelStats
	if opts.Programs.LogLevel != wantLevel {
		t.Errorf("LogLevel = %#x, want %#x", opts.Programs.LogLevel, wantLevel)
	}
	if opts.Programs.LogSizeStart != defaultVerboseLogSize {
		t.Errorf("LogSizeStart = %d, want %d", opts.Programs.LogSizeStart, defaultVerboseLogSize)
	}
}

func TestApplyVerifierLogOptions_CustomBufferSize(t *testing.T) {
	t.Setenv(envBPFLogLevel, "instructions")
	t.Setenv(envBPFLogSize, "262144")
	var opts ebpf.CollectionOptions
	applyVerifierLogOptions(&opts)

	if opts.Programs.LogSizeStart != 262144 {
		t.Errorf("LogSizeStart = %d, want 262144", opts.Programs.LogSizeStart)
	}
}

func TestApplyVerifierLogOptions_KernelTypesUntouched(t *testing.T) {
	t.Setenv(envBPFLogLevel, "verbose")
	var opts ebpf.CollectionOptions
	applyVerifierLogOptions(&opts)

	if opts.Programs.KernelTypes != nil {
		t.Errorf("KernelTypes should remain nil — applyVerifierLogOptions must not alter unrelated fields")
	}
}

func TestLogVerifierFailure_NilDoesNotPanic(t *testing.T) {
	logVerifierFailure(nil) // must not panic
}

func TestLogVerifierFailure_NonVerifierErrorIsNoop(t *testing.T) {
	logVerifierFailure(errPlain)
}

// TestVerifierErrorFormatting_PlusVPrintsFullLog proves the formatting choice
// in logVerifierFailure is correct: cilium/ebpf's default Error() truncates
// to the last 1-2 lines + "(N line(s) omitted)", while %+v renders the
// entire log.
func TestVerifierErrorFormatting_PlusVPrintsFullLog(t *testing.T) {
	logLines := []string{
		"0: (b7) r1 = 1                  ; R1_w=1",
		"1: (61) r2 = *(u32 *)(r1 +0)",
		"R1 pointer arithmetic on PTR_TO_FUNC prohibited",
		"verifier rejected program",
		"Lockdown: podtrace: use of bpf to read kernel RAM is restricted",
		"see man kernel_lockdown.7 for details",
		"program 'uretprobe_rd_kafka_consumer_poll' cannot use this helper in this context",
	}
	ve := &ebpf.VerifierError{
		Cause: errPlain,
		Log:   logLines,
	}

	truncated := ve.Error()
	full := fmt.Sprintf("%+v", ve)

	if strings.Contains(truncated, logLines[0]) {
		t.Errorf("default Error() unexpectedly includes early log line — cilium/ebpf changed behaviour?\n got: %s", truncated)
	}
	if !strings.Contains(truncated, "line(s) omitted") {
		t.Errorf("default Error() must indicate truncation; got: %s", truncated)
	}

	for _, line := range logLines {
		if !strings.Contains(full, line) {
			t.Errorf("%%+v formatting must include every log line; missing %q\n  full: %s", line, full)
		}
	}
	if strings.Contains(full, "line(s) omitted") {
		t.Errorf("%%+v must not truncate; got: %s", full)
	}
}

// TestVerifierErrorFormatting_WrappedErrorStillReachable proves
// logVerifierFailure works even when the caller has wrapped the VerifierError
// further (e.g. tracer/errors.go's NewCollectionError), because we use
// errors.As which walks the wrapping chain.
func TestVerifierErrorFormatting_WrappedErrorStillReachable(t *testing.T) {
	ve := &ebpf.VerifierError{
		Cause: errPlain,
		Log:   []string{"single line"},
	}
	wrapped := fmt.Errorf("failed to create eBPF collection: %w", ve)

	var got *ebpf.VerifierError
	if !errors.As(wrapped, &got) {
		t.Fatalf("errors.As must unwrap to *ebpf.VerifierError through fmt.Errorf chains")
	}
	if got != ve {
		t.Errorf("unwrapped error must be the original instance")
	}
}

var errPlain = &plainErr{msg: "not a verifier error"}

type plainErr struct{ msg string }

func (e *plainErr) Error() string { return e.msg }