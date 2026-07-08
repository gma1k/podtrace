package probes

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"

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

// openELFWithinRoot opens rel as an ELF resolved strictly within rootDir using
// openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS): a "..", an absolute segment,
// or a symlink in the container-controlled path cannot escape rootDir, closing
// the .gnu_debuglink traversal that let the root agent open host files such as
// /proc/kcore.
func openELFWithinRoot(rootDir, rel string) (*elf.File, error) {
	rootFd, err := unix.Open(rootDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(rootFd) }()

	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(rootFd, rel, how)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), rel)
	defer func() { _ = file.Close() }()

	fi, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("debug file %q is not a regular file", rel)
	}
	if fi.Size() > maxELFFileSize {
		return nil, fmt.Errorf("debug file %q too large: %d bytes", rel, fi.Size())
	}
	buf := make([]byte, fi.Size())
	if _, err := io.ReadFull(file, buf); err != nil {
		return nil, err
	}
	return elf.NewFile(bytes.NewReader(buf))
}

// recoverParse converts a panic from an ELF/DWARF/gosym parser, a malformed
// untrusted binary, into a logged warning so a hostile pod cannot crash the
// agent.
func recoverParse(where string) {
	if r := recover(); r != nil {
		logger.Warn("recovered from panic parsing untrusted binary",
			zap.String("where", where), zap.Any("panic", r))
	}
}