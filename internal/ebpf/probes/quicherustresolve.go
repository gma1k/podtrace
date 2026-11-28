package probes

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/logger"
)

var quicheRustSendRequestPattern = []string{"6quiche", "2h3", "12send_request"}

const maxQuicheRustAttachments = 4

// AttachQuicheRustProbes attaches a uprobe on
// quiche::h3::Connection::send_request in a statically-linked Rust binary.
func AttachQuicheRustProbes(coll *ebpf.Collection, pid uint32) []link.Link {
	return attachQuicheRustProbes(coll, pid, false)
}

// attachQuicheRustProbes attaches the quiche crate uprobe for pid. With
// processScoped it attaches only one at an offset from a debug file, which
// covers pid alone.
func attachQuicheRustProbes(coll *ebpf.Collection, pid uint32, processScoped bool) (links []link.Link) {
	defer recoverParse("AttachQuicheRustProbes")
	if pid == 0 || runtime.GOARCH != "amd64" {
		return links
	}
	prog := coll.Programs["uprobe_quiche_rs_send_request"]
	if prog == nil {
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

	vaddrs := findSymbolsContaining(f, maxQuicheRustAttachments, quicheRustSendRequestPattern...)
	fromDebugFile := false
	if processScoped && len(vaddrs) > 0 {
		return links
	}
	if len(vaddrs) == 0 {
		if dbg, src := openDebugInfo(f, pid); dbg != nil {
			defer func() { _ = dbg.Close() }()
			vaddrs = findSymbolsContaining(dbg, maxQuicheRustAttachments, quicheRustSendRequestPattern...)
			fromDebugFile = true
			if len(vaddrs) > 0 {
				logger.Debug("quiche crate symbols resolved via debug file",
					zap.Uint32("pid", pid), zap.String("source", src))
			}
		}
	}

	for _, opts := range (rustSymbolSource{target: f, pid: pid}).offsets(vaddrs, fromDebugFile) {
		if l, err := exe.Uprobe("", prog, opts); err == nil {
			links = append(links, l)
			logger.Debug("quiche crate send_request uprobe attached",
				zap.Uint32("pid", pid), zap.Uint64("offset", opts.Address))
		} else {
			logger.Debug("quiche crate send_request uprobe not attached",
				zap.Uint32("pid", pid), zap.Error(err))
		}
	}
	return links
}
