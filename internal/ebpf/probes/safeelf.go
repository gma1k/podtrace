package probes

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/logger"
)

// The probes package resolves uprobe offsets by parsing the target's own
// executable and debug files, which for a traced pod are attacker-controlled.
const (
	maxELFFileSize = int64(1) << 30

	maxELFSectionSize = uint64(512) << 20

	maxDWARFTotalSize = uint64(512) << 20
)

// openELFCapped opens a fixed-path ELF (e.g. /proc/<pid>/exe) after rejecting
// oversized files.
func openELFCapped(path string) (*elf.File, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxELFFileSize {
		return nil, fmt.Errorf("elf %q too large to parse safely: %d bytes", path, fi.Size())
	}
	return elf.Open(path)
}

// sectionDataCapped returns sec.Data only when the section's declared size is
// within maxELFSectionSize, so a lying/huge section header cannot drive a
// multi-GB allocation. A nil section yields (nil, nil).
func sectionDataCapped(sec *elf.Section) ([]byte, error) {
	if sec == nil {
		return nil, nil
	}
	if sec.Size > maxELFSectionSize {
		return nil, fmt.Errorf("section %q too large: %d bytes", sec.Name, sec.Size)
	}
	return sec.Data()
}

// symbolSectionWithinCap reports whether the named symbol table is small enough
// to parse; debug/elf.Symbols allocates proportional to the section size, so a
// huge .symtab/.dynsym must be skipped rather than parsed.
func symbolSectionWithinCap(f *elf.File, section string) bool {
	sec := f.Section(section)
	return sec != nil && sec.Size <= maxELFSectionSize
}

// dwarfWithinCap reports whether the combined DWARF sections are within cap,
// bounding DWARF() memory (including decompression of .zdebug_*).
func dwarfWithinCap(f *elf.File) bool {
	var total uint64
	for _, s := range f.Sections {
		if strings.HasPrefix(s.Name, ".debug_") || strings.HasPrefix(s.Name, ".zdebug_") {
			total += s.Size
			if total > maxDWARFTotalSize {
				return false
			}
		}
	}
	return true
}

// safeDebugName reports whether a .gnu_debuglink filename is a plain basename.
// The name is attacker-controlled bytes.
func safeDebugName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsRune(name, '/') && !strings.ContainsRune(name, 0)
}


// recoverParse converts a panic from an ELF/DWARF/gosym parser, a malformed
// untrusted binary, into a logged warning so a hostile pod cannot crash the
// agent. from an ELF/DWARF/gosym parser, a malformed
// untrusted binary, into a logged warning so a hostile pod cannot crash the
// agent.
func recoverParse(where string) {
	if r := recover(); r != nil {
		logger.Warn("recovered from panic parsing untrusted binary",
			zap.String("where", where), zap.Any("panic", r))
	}
}