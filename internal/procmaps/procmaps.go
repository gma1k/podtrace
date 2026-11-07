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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/gma1k/podtrace/internal/procfs"
)

// fixedColumns is the number of whitespace-separated columns the kernel writes
// before the pathname: address range, permissions, file offset, device, inode.
const fixedColumns = 5

// deletedSuffix is appended by the kernel once the backing file is unlinked.
const deletedSuffix = " (deleted)"

const MaxLineBytes = 8 << 10

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
	// Device is the raw "<major>:<minor>" column and Inode the backing
	// file's inode number, 0 for an anonymous mapping. Together they name
	// the mapped file within one maps listing.
	Device string
	Inode  uint64
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

	var offsetField, inodeField string
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
		case 3:
			e.Device = rest[:width]
		case 4:
			inodeField = rest[:width]
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

	if inode, err := strconv.ParseUint(inodeField, 10, 64); err == nil {
		e.Inode = inode
	}

	path := strings.TrimLeft(rest, " \t")
	if strings.HasSuffix(path, deletedSuffix) {
		e.Deleted = true
		path = strings.TrimSuffix(path, deletedSuffix)
	}
	e.Path = path

	return e, true
}

// Scan streams a maps file through visit one line at a time, skipping lines
// that do not have the expected shape or exceed MaxLineBytes, until visit
// returns false. Only the entries visit keeps stay in memory, which matters
// because a traced process controls the length of its own maps file: up to
// vm.max_map_count lines of up to PATH_MAX each.
func Scan(r io.Reader, visit func(Entry) bool) error {
	br := bufio.NewReaderSize(r, MaxLineBytes)
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
		} else if len(line) > 0 {
			if e, ok := ParseLine(string(bytes.TrimSuffix(line, []byte{'\n'}))); ok && !visit(e) {
				return nil
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// ScanProcess streams /proc/<pid>/maps through visit; see Scan.
func ScanProcess(pid uint32, visit func(Entry) bool) error {
	f, err := procfs.Open(fmt.Sprintf("%d/maps", pid))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return Scan(f, visit)
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
