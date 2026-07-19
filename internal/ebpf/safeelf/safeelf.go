// Package safeelf parses attacker-controlled ELF binaries, a traced pod's
// own executable and debug files, within hard resource caps and with panic
// recovery, so a hostile binary cannot OOM or crash the privileged agent.
package safeelf

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/logger"
)

const (
	MaxFileSize = int64(1) << 30 // 1 GiB

	MaxSectionSize = uint64(512) << 20 // 512 MiB

	MaxDWARFTotalSize = uint64(512) << 20 // 512 MiB
)

// Open opens a fixed-path ELF (e.g. /proc/<pid>/exe) after rejecting
// oversized files.
func Open(path string) (*elf.File, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > MaxFileSize {
		return nil, fmt.Errorf("elf %q too large to parse safely: %d bytes", path, fi.Size())
	}
	return elf.Open(path)
}

// SectionData returns sec.Data only when the section's declared size is within
// MaxSectionSize, so a lying/huge section header cannot drive a multi-GB
// allocation.
func SectionData(sec *elf.Section) ([]byte, error) {
	if sec == nil {
		return nil, nil
	}
	if sec.Size > MaxSectionSize {
		return nil, fmt.Errorf("section %q too large: %d bytes", sec.Name, sec.Size)
	}
	return sec.Data()
}

// SymbolSectionWithinCap reports whether the named symbol table is small
// enough to parse.
func SymbolSectionWithinCap(f *elf.File, section string) bool {
	sec := f.Section(section)
	return sec != nil && sec.Size <= MaxSectionSize
}

// DWARFWithinCap reports whether the combined DWARF sections are within cap,
// bounding DWARF() memory (including decompression of .zdebug_*).
func DWARFWithinCap(f *elf.File) bool {
	var total uint64
	for _, s := range f.Sections {
		if strings.HasPrefix(s.Name, ".debug_") || strings.HasPrefix(s.Name, ".zdebug_") {
			total += s.Size
			if total > MaxDWARFTotalSize {
				return false
			}
		}
	}
	return true
}

// SafeDebugName reports whether a .gnu_debuglink filename is a plain basename.
func SafeDebugName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsRune(name, '/') && !strings.ContainsRune(name, 0)
}

// RecoverParse converts a panic from an ELF/DWARF/gosym parser on a malformed
// untrusted binary into a logged warning so a hostile pod cannot crash the
// agent.
func RecoverParse(where string) {
	if r := recover(); r != nil {
		logger.Warn("recovered from panic parsing untrusted binary",
			zap.String("where", where), zap.Any("panic", r))
	}
}
