// Package procmaps parses /proc/<pid>/maps.
//
// The pathname on a maps line is the entire remainder of the line and must
// never be read as a whitespace-separated field. The kernel emits it verbatim
// through seq_path and does not escape spaces, so a file named
// "libssl.so.3 X" produces a line whose sixth whitespace-separated token is
// "libssl.so.3" — the name of a different file that may well exist elsewhere.
// Taking that token lets the traced process choose which path the reader
// believes it mapped, which for a privileged reader that then attaches uprobes
// is a way out of the target's rootfs.
//
// A pathname whose own leading characters are spaces cannot be recovered from
// this file at all, because the kernel pads to a fixed column with the same
// character. Callers that must be certain of the backing file should treat
// /proc/<pid>/map_files as authoritative and the pathname only as a hint.
package procmaps

import (
	"strconv"
	"strings"
)

// fixedColumns is the number of whitespace-separated columns the kernel writes
// before the pathname: address range, permissions, file offset, device, inode.
const fixedColumns = 5

// deletedSuffix is appended by the kernel once the backing file is unlinked.
const deletedSuffix = " (deleted)"

// Entry is one parsed line of /proc/<pid>/maps.
type Entry struct {
	// AddrRange is the raw "<hex>-<hex>" column, which is also the name of
	// the corresponding /proc/<pid>/map_files entry.
	AddrRange string
	Start     uint64
	End       uint64
	Perms     string
	// Offset is the file offset the mapping starts at.
	Offset uint64
	// Path is the backing file's pathname with any " (deleted)" marker
	// removed, empty for an anonymous mapping.
	Path string
	// Deleted reports that the backing file has been unlinked.
	Deleted bool
}

// Executable reports whether the mapping carries the execute bit, i.e. holds
// the code segment a uprobe would attach to.
func (e Entry) Executable() bool { return strings.Contains(e.Perms, "x") }

// Named reports whether the entry is file-backed, as opposed to an anonymous
// mapping or a kernel pseudo-mapping such as [stack], [heap] or [vdso].
func (e Entry) Named() bool {
	return e.Path != "" && !strings.HasPrefix(e.Path, "[")
}

// ParseLine parses one line of /proc/<pid>/maps, reporting false when the line
// does not have the shape the kernel writes.
func ParseLine(line string) (Entry, bool) {
	var e Entry
	rest := line

	var offsetField string
	for column := 0; column < fixedColumns; column++ {
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			return Entry{}, false
		}
		width := strings.IndexAny(rest, " \t")
		if width < 0 {
			if column != fixedColumns-1 {
				return Entry{}, false
			}
			width = len(rest)
		}
		switch column {
		case 0:
			e.AddrRange = rest[:width]
		case 1:
			e.Perms = rest[:width]
		case 2:
			offsetField = rest[:width]
		}
		rest = rest[width:]
	}

	start, end, ok := parseAddrRange(e.AddrRange)
	if !ok {
		return Entry{}, false
	}
	e.Start, e.End = start, end

	offset, err := strconv.ParseUint(offsetField, 16, 64)
	if err != nil {
		return Entry{}, false
	}
	e.Offset = offset

	path := strings.TrimLeft(rest, " \t")
	if strings.HasSuffix(path, deletedSuffix) {
		e.Deleted = true
		path = strings.TrimSuffix(path, deletedSuffix)
	}
	e.Path = path

	return e, true
}

// Parse parses the contents of a /proc/<pid>/maps file, skipping lines that do
// not have the expected shape.
func Parse(data []byte) []Entry {
	lines := strings.Split(string(data), "\n")
	entries := make([]Entry, 0, len(lines))
	for _, line := range lines {
		if e, ok := ParseLine(line); ok {
			entries = append(entries, e)
		}
	}
	return entries
}

func parseAddrRange(s string) (uint64, uint64, bool) {
	dash := strings.IndexByte(s, '-')
	if dash <= 0 || dash == len(s)-1 {
		return 0, 0, false
	}
	start, err := strconv.ParseUint(s[:dash], 16, 64)
	if err != nil {
		return 0, 0, false
	}
	end, err := strconv.ParseUint(s[dash+1:], 16, 64)
	if err != nil {
		return 0, 0, false
	}
	return start, end, true
}
