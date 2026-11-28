package probes

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/safeconv"
)

// sslOffsets holds the file offsets (within the target executable) of the TLS
// read/write entry points, suitable for link.UprobeOptions.Address, plus a
// label describing how they were resolved.
type sslOffsets struct {
	write  uint64
	read   uint64
	source string
}

// resolveSSLOffsets locates SSL_write/SSL_read in a statically-linked,
// symbol-stripped executable that executableExportsSSL could not gate (no
// SSL_write in .symtab/.dynsym). exePath must name the pinned file the
// uprobes will be attached to.
func resolveSSLOffsets(exePath string, pid uint32) (off sslOffsets, ok bool) {
	defer recoverParse("resolveSSLOffsets")
	target, err := openELFCapped(exePath)
	if err != nil {
		return sslOffsets{}, false
	}
	defer func() { _ = target.Close() }()

	dbg, source := openDebugInfo(target, pid)
	if dbg == nil {
		return sslOffsets{}, false
	}
	defer func() { _ = dbg.Close() }()

	wv, okW := symbolVaddr(dbg, "SSL_write")
	rv, okR := symbolVaddr(dbg, "SSL_read")
	if !okW || !okR {
		return sslOffsets{}, false
	}
	wOff, okW := codeFileOffset(target, wv)
	rOff, okR := codeFileOffset(target, rv)
	if !okW || !okR {
		return sslOffsets{}, false
	}
	return sslOffsets{write: wOff, read: rOff, source: source}, true
}

// errDebugFileMismatch refuses a debug file that is not the one built with
// the target.
var errDebugFileMismatch = errors.New("debug file does not match the executable")

// openDebugInfo finds and opens a separate debug file for pid's executable
// within pid's own rootfs, returning the opened ELF and a source label, or
// (nil, "") if none is found. Every candidate is resolved inside that root,
// the executable's directory as the target itself sees it.
func openDebugInfo(target *elf.File, pid uint32) (*elf.File, string) {
	if pid == 0 {
		return nil, ""
	}
	root := procRoot(pid)

	buildID := elfBuildID(target)
	if len(buildID) > 2 {
		rel := filepath.Join("usr/lib/debug/.build-id", buildID[:2], buildID[2:]+".debug")
		if f, err := openVerifiedELFWithinRoot(root, rel, buildIDMatches(buildID)); err == nil {
			return f, "debug-buildid"
		}
	}
	name, crc, hasCRC := debugLink(target)
	if !safeDebugName(name) {
		return nil, ""
	}
	accept := buildIDMatches(buildID)
	if buildID == "" {
		if !hasCRC {
			return nil, ""
		}
		accept = crcMatches(crc)
	}
	var candidates []string
	if dir := executableDirInTarget(pid); dir != "" {
		candidates = append(candidates,
			filepath.Join(dir, name),
			filepath.Join(dir, ".debug", name),
			filepath.Join("usr/lib/debug", dir, name),
		)
	}
	candidates = append(candidates, filepath.Join("usr/lib/debug", name))
	for _, rel := range candidates {
		if f, err := openVerifiedELFWithinRoot(root, rel, accept); err == nil {
			return f, "debug-link"
		}
	}
	return nil, ""
}

// buildIDMatches accepts a debug file that carries buildID.
func buildIDMatches(buildID string) func(*os.File, os.FileInfo, *elf.File) bool {
	return func(_ *os.File, _ os.FileInfo, f *elf.File) bool {
		return buildID != "" && elfBuildID(f) == buildID
	}
}

// crcMatches accepts a debug file whose CRC32 is crc.
func crcMatches(crc uint32) func(*os.File, os.FileInfo, *elf.File) bool {
	return func(raw *os.File, fi os.FileInfo, _ *elf.File) bool {
		h := crc32.NewIEEE()
		if _, err := io.Copy(h, io.NewSectionReader(raw, 0, fi.Size())); err != nil {
			return false
		}
		return h.Sum32() == crc
	}
}

// executableDirInTarget returns the directory of pid's executable as the
// target sees it in its own mount namespace, or "" when it cannot be read.
func executableDirInTarget(pid uint32) string {
	target, err := os.Readlink(filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe"))
	if err != nil {
		return ""
	}
	target = strings.TrimSuffix(target, " (deleted)")
	if !filepath.IsAbs(target) {
		return ""
	}
	return filepath.Dir(target)
}

// elfBuildID parses the GNU build-id (.note.gnu.build-id) into a lowercase hex
// string, or "" if absent.
func elfBuildID(f *elf.File) string {
	data, err := safeelf.SectionDataWithin(f.Section(".note.gnu.build-id"), safeelf.MaxNoteSize)
	if err != nil || len(data) < 12 {
		return ""
	}
	namesz := uint64(f.ByteOrder.Uint32(data[0:4]))
	descsz := uint64(f.ByteOrder.Uint32(data[4:8]))
	nameEnd := 12 + (namesz+3)&^3
	if descsz == 0 || nameEnd+descsz > uint64(len(data)) {
		return ""
	}
	return hex.EncodeToString(data[nameEnd : nameEnd+descsz])
}

// debugLink returns the filename recorded in .gnu_debuglink and the CRC32 of
// the debug file that follows it, 4-byte aligned. hasCRC is false when the
// section ends before the CRC.
func debugLink(f *elf.File) (name string, crc uint32, hasCRC bool) {
	data, err := safeelf.SectionDataWithin(f.Section(".gnu_debuglink"), safeelf.MaxNoteSize)
	if err != nil {
		return "", 0, false
	}
	i := bytes.IndexByte(data, 0)
	if i <= 0 {
		return "", 0, false
	}
	crcOff := (i + 1 + 3) &^ 3
	if crcOff+4 > len(data) {
		return string(data[:i]), 0, false
	}
	return string(data[:i]), f.ByteOrder.Uint32(data[crcOff : crcOff+4]), true
}

// attachSSLByOffset attaches the SSL_write/SSL_read uprobes (and their
// return probes) to the target executable at offsets resolved from a debug
// file, used when no symbol is available for the linker to bind against.
func attachSSLByOffset(coll *ebpf.Collection, exe uprobeTarget, pid uint32, off sslOffsets) []link.Link {
	var links []link.Link
	attach := func(progName string, addr uint64, ret bool) {
		prog := coll.Programs[progName]
		if prog == nil {
			return
		}
		opts := untrustedOffsetOptions(addr, pid)
		var l link.Link
		var aerr error
		if ret {
			l, aerr = exe.Uretprobe("", prog, opts)
		} else {
			l, aerr = exe.Uprobe("", prog, opts)
		}
		if aerr == nil {
			links = append(links, l)
		} else {
			logger.Debug("TLS offset attach failed", zap.String("prog", progName), zap.Error(aerr))
		}
	}
	attach("uprobe_SSL_write", off.write, false)
	attach("uretprobe_SSL_write", off.write, true)
	attach("uprobe_SSL_read", off.read, false)
	attach("uretprobe_SSL_read", off.read, true)
	return links
}

// AttachProcessScopedProbes attaches, for another process of a binary whose
// probes are already attached, the uprobes that cover only the process they
// are attached for.
func AttachProcessScopedProbes(coll *ebpf.Collection, pid uint32) []link.Link {
	if pid == 0 || coll == nil || !hasDebugFile(pid) {
		return nil
	}
	var links []link.Link
	links = append(links, attachStrippedExecutableTLS(coll, pid)...)
	links = append(links, attachRustlsProbes(coll, pid, true)...)
	links = append(links, attachQuicheRustProbes(coll, pid, true)...)
	return links
}

// hasDebugFile reports whether pid's executable has a separate debug file in
// its rootfs, the only source of process-scoped uprobes. Most do not, and this
// is far cheaper than walking their symbol tables.
func hasDebugFile(pid uint32) (found bool) {
	defer recoverParse("hasDebugFile")
	path := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe")
	file, _, err := openAttachTarget(path)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	f, err := openELFCapped(safeelf.PinnedPath(file, path))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	dbg, _ := openDebugInfo(f, pid)
	if dbg == nil {
		return false
	}
	_ = dbg.Close()
	return true
}

// untrustedOffsetOptions places a uprobe at an offset that came from a file
// the traced pod controls, filtered to pid: the kernel then writes the
// breakpoint only into that process's memory, never into another process
// that maps the same file.
func untrustedOffsetOptions(addr uint64, pid uint32) *link.UprobeOptions {
	return &link.UprobeOptions{Address: addr, PID: safeconv.Uint64ToInt(uint64(pid))}
}
