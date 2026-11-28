// Package safeelf parses attacker-controlled ELF binaries, a traced pod's
// own executable and debug files, within hard resource caps and with panic
// recovery, so a hostile binary cannot OOM or crash the privileged agent.
package safeelf

import (
	"debug/elf"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/logger"
)

// Every cap is a ceiling on memory the agent allocates for one read. Section
// sizes are declared by the file, and a sparse file makes any declared size
// free on disk, so none of them may be larger than the agent can afford.
const (
	MaxFileSize = int64(1) << 30 // 1 GiB

	MaxSectionSize = uint64(128) << 20 // 128 MiB

	MaxDWARFTotalSize = uint64(256) << 20 // 256 MiB

	MaxSymbolTableSize = uint64(64) << 20 // 64 MiB

	MaxMaterializedSymbolBytes = uint64(192) << 20 // 192 MiB

	MaxNoteSize = uint64(4) << 10 // 4 KiB
)

// OpenRegular opens path for reading only when it is a regular file within
// MaxFileSize.
func OpenRegular(path string) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0) // #nosec G304 -- callers pass paths already confined to the target's rootfs; this open only checks the file type.
	if err != nil {
		return nil, nil, err
	}
	fi, err := checkRegular(f, path)
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// checkRegular returns f's FileInfo when f is a regular file within
// MaxFileSize.
func checkRegular(f *os.File, name string) (os.FileInfo, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", name)
	}
	if fi.Size() > MaxFileSize {
		return nil, fmt.Errorf("elf %q too large to parse safely: %d bytes", name, fi.Size())
	}
	return fi, nil
}

// Open opens a fixed-path ELF (e.g. /proc/<pid>/exe) after rejecting
// oversized and non-regular files. The ELF is parsed from the file that was
// checked, not from a second lookup of path.
func Open(path string) (*elf.File, error) {
	f, _, err := OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return elf.Open(PinnedPath(f, path))
}

// SectionData returns sec's contents when its declared size is within
// MaxSectionSize.
func SectionData(sec *elf.Section) ([]byte, error) {
	return SectionDataWithin(sec, MaxSectionSize)
}

// SectionDataWithin returns sec's contents when its declared size is within
// limit. The buffer is allocated once at the declared size, so a read costs
// that size and no more.
func SectionDataWithin(sec *elf.Section, limit uint64) ([]byte, error) {
	if sec == nil {
		return nil, nil
	}
	if sec.Size > limit {
		return nil, fmt.Errorf("section %q too large: %d bytes", sec.Name, sec.Size)
	}
	return readSection(sec, sec.Size)
}

// SectionPrefix returns at most the first n bytes of sec, for a caller that
// only searches the contents and can do without the rest.
func SectionPrefix(sec *elf.Section, n uint64) ([]byte, error) {
	if sec == nil {
		return nil, nil
	}
	return readSection(sec, min(sec.Size, n))
}

func readSection(sec *elf.Section, n uint64) ([]byte, error) {
	if sec.Type == elf.SHT_NOBITS {
		return nil, fmt.Errorf("section %q occupies no file space", sec.Name)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(sec.Open(), buf); err != nil {
		return nil, fmt.Errorf("section %q: %w", sec.Name, err)
	}
	return buf, nil
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
