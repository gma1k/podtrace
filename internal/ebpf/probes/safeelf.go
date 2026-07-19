package probes

import (
	"debug/elf"

	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/ebpf/safeelf"
	"github.com/podtrace/podtrace/internal/logger"
)

// The safe-ELF caps and primitives live in internal/ebpf/safeelf, the single
// source of truth shared with internal/usdt.

const maxELFFileSize = safeelf.MaxFileSize

func openELFCapped(path string) (*elf.File, error) { return safeelf.Open(path) }

func sectionDataCapped(sec *elf.Section) ([]byte, error) { return safeelf.SectionData(sec) }

func symbolSectionWithinCap(f *elf.File, section string) bool {
	return safeelf.SymbolSectionWithinCap(f, section)
}

func dwarfWithinCap(f *elf.File) bool { return safeelf.DWARFWithinCap(f) }

func safeDebugName(name string) bool { return safeelf.SafeDebugName(name) }

// recoverParse keeps its own recover here rather than delegating: recover()
// only takes effect when called directly by the deferred function, so a
// `defer recoverParse(...)` cannot forward to safeelf.RecoverParse.
func recoverParse(where string) {
	if r := recover(); r != nil {
		logger.Warn("recovered from panic parsing untrusted binary",
			zap.String("where", where), zap.Any("panic", r))
	}
}
