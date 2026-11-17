package probes

import (
	"bytes"
	"debug/elf"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
	"github.com/gma1k/podtrace/internal/logger"
)

// maxCommentPrefix bounds how much of .comment is searched for the producer
// string. Linkers merge the per-object strings, so real sections are a few
// hundred bytes.
const maxCommentPrefix = 64 << 10

// elfIsRust reports whether an ELF was produced by rustc, detected via the
// ".comment" section.
func elfIsRust(f *elf.File) bool {
	data, err := safeelf.SectionPrefix(f.Section(".comment"), maxCommentPrefix)
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte("rustc"))
}

var (
	rustlsWriteSymbolPattern = []string{"rustls", "Writer", "5write"}
	rustlsReadSymbolPattern  = []string{"rustls", "Reader", "4read"}
)

// rustSymbolSource locates functions in a Rust binary, from its own symbol
// table or, for a stripped binary, from its debug file.
type rustSymbolSource struct {
	target *elf.File
	pid    uint32
}

// offsets maps every resolved virtual address to its attach options.
func (s rustSymbolSource) offsets(vaddrs []uint64, fromDebugFile bool) []*link.UprobeOptions {
	var out []*link.UprobeOptions
	for _, vaddr := range vaddrs {
		off, ok := codeFileOffset(s.target, vaddr)
		if !ok {
			continue
		}
		if fromDebugFile {
			out = append(out, untrustedOffsetOptions(off, s.pid))
			continue
		}
		out = append(out, &link.UprobeOptions{Address: off})
	}
	return out
}

// AttachRustlsProbes attaches uprobes on rustls' plaintext boundary in a
// statically-linked Rust binary: <rustls::conn::Writer as io::Write>::write
// (outbound) and <rustls::conn::Reader as io::Read>::read (inbound), capturing
// HTTP/1.x, HTTP/2 and gRPC L7 over rustls TLS before encryption / after
// decryption.
func AttachRustlsProbes(coll *ebpf.Collection, pid uint32) (links []link.Link) {
	defer recoverParse("AttachRustlsProbes")
	if pid == 0 {
		return links
	}
	writeProg := coll.Programs["uprobe_rustls_write"]
	writeRetProg := coll.Programs["uretprobe_rustls_write"]
	readProg := coll.Programs["uprobe_rustls_read"]
	readRetProg := coll.Programs["uretprobe_rustls_read"]
	if writeProg == nil || writeRetProg == nil || readProg == nil || readRetProg == nil {
		return links
	}

	exe, err := openExecutable(filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe"))
	if err != nil {
		return links
	}
	defer func() { _ = exe.Close() }()
	f, err := openELFCapped(exe.Path())
	if err != nil {
		return links
	}
	defer func() { _ = f.Close() }()
	if !elfIsRust(f) {
		return links
	}

	src := rustSymbolSource{target: f, pid: pid}
	writeVaddrs := findSymbolsContaining(f, 1, rustlsWriteSymbolPattern...)
	readVaddrs := findSymbolsContaining(f, 1, rustlsReadSymbolPattern...)
	fromDebugFile := false
	if len(writeVaddrs) == 0 && len(readVaddrs) == 0 {
		if dbg, from := openDebugInfo(f, pid); dbg != nil {
			defer func() { _ = dbg.Close() }()
			writeVaddrs = findSymbolsContaining(dbg, 1, rustlsWriteSymbolPattern...)
			readVaddrs = findSymbolsContaining(dbg, 1, rustlsReadSymbolPattern...)
			fromDebugFile = true
			if len(writeVaddrs) > 0 || len(readVaddrs) > 0 {
				logger.Debug("rustls symbols resolved via debug file",
					zap.Uint32("pid", pid), zap.String("source", from))
			}
		}
	}

	for _, opts := range src.offsets(writeVaddrs, fromDebugFile) {
		entry, err := exe.Uprobe("", writeProg, opts)
		if err != nil {
			logger.Debug("rustls write uprobe not attached", zap.Uint32("pid", pid), zap.Error(err))
		} else if ret, err := exe.Uretprobe("", writeRetProg, opts); err != nil {
			_ = entry.Close()
			logger.Debug("rustls write uretprobe not attached", zap.Uint32("pid", pid), zap.Error(err))
		} else {
			links = append(links, entry, ret)
			logger.Debug("rustls write uprobes attached", zap.Uint32("pid", pid), zap.Uint64("offset", opts.Address))
		}
	}
	for _, opts := range src.offsets(readVaddrs, fromDebugFile) {
		if l, err := exe.Uprobe("", readProg, opts); err == nil {
			links = append(links, l)
		}
		if l, err := exe.Uretprobe("", readRetProg, opts); err == nil {
			links = append(links, l)
		}
		logger.Debug("rustls read uprobes attached", zap.Uint32("pid", pid), zap.Uint64("offset", opts.Address))
	}
	return links
}
