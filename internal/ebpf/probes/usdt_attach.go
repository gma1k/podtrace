package probes

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/ebpf/safeelf"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/usdt"
)

// usdtArgValue mirrors `struct usdt_arg` in bpf/maps.h (16 bytes with the
// 4-byte pad the C compiler inserts before the 8-byte disp).
type usdtArgValue struct {
	Size   int8
	Kind   uint8
	RegOff uint16
	_      [4]byte
	Disp   int64
}

// usdtProbeValue mirrors `struct usdt_probe` in bpf/maps.h. Field sizes MUST
// match USDT_PROVIDER_LEN / USDT_NAME_LEN / USDT_MAX_ARGS there (200 bytes).
type usdtProbeValue struct {
	Provider [64]byte
	Name     [64]byte
	NArgs    uint8
	_        [7]byte
	Args     [usdt.MaxArgs]usdtArgValue
}

// usdtCookieSeq hands out globally-unique uprobe attach cookies.
var usdtCookieSeq atomic.Uint64

const maxUSDTProbesPerBinary = 256

// AttachUSDTProbes discovers the USDT probes in the target pid's executable and
// attaches uprobe_usdt at each probe PC, enabling the SDT semaphore when one is
// present (and the kernel supports ref_ctr_offset).
func AttachUSDTProbes(coll *ebpf.Collection, pid uint32) []link.Link {
	defer safeelf.RecoverParse("probes.AttachUSDTProbes")

	var links []link.Link
	if pid == 0 || !config.USDTEnabled {
		return links
	}
	prog := coll.Programs["uprobe_usdt"]
	pmap := coll.Maps["usdt_probes"]
	if prog == nil || pmap == nil {
		return links
	}

	exePath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe")
	f, err := safeelf.Open(exePath)
	if err != nil {
		return links
	}
	defer func() { _ = f.Close() }()

	found, err := usdt.ScanFile(f)
	if err != nil || len(found) == 0 {
		return links
	}

	exe, err := link.OpenExecutable(exePath)
	if err != nil {
		return links
	}

	semSupported := uprobeRefCtrOffsetSupported()
	for i := range found {
		if len(links) >= maxUSDTProbesPerBinary {
			logger.Debug("usdt probe cap reached; remaining probes skipped",
				zap.Uint32("pid", pid), zap.Int("cap", maxUSDTProbesPerBinary))
			break
		}
		p := found[i]
		addr, ok := vaddrToFileOffset(f, p.PC)
		if !ok {
			continue
		}

		cookie := usdtCookieSeq.Add(1)
		val := usdtProbeValue{}
		copyCString(val.Provider[:], p.Provider)
		copyCString(val.Name[:], p.Name)
		nargs := len(p.Args)
		if nargs > usdt.MaxArgs {
			nargs = usdt.MaxArgs
		}
		val.NArgs = uint8(nargs)
		for j := 0; j < nargs; j++ {
			val.Args[j] = usdtArgValue{
				Size:   p.Args[j].Size,
				Kind:   uint8(p.Args[j].Kind),
				RegOff: p.Args[j].RegOff,
				Disp:   p.Args[j].Disp,
			}
		}
		if err := pmap.Update(cookie, &val, ebpf.UpdateAny); err != nil {
			logger.Debug("usdt map update failed", zap.Uint32("pid", pid), zap.Error(err))
			continue
		}

		opts := &link.UprobeOptions{Address: addr, Cookie: cookie}
		if p.SemAddr != 0 && semSupported {
			if semOff, ok := vaddrToFileOffset(f, p.SemAddr); ok {
				opts.RefCtrOffset = semOff
			}
		}

		l, err := exe.Uprobe("", prog, opts)
		if err != nil && opts.RefCtrOffset != 0 {
			opts.RefCtrOffset = 0
			l, err = exe.Uprobe("", prog, opts)
		}
		if err != nil {
			_ = pmap.Delete(cookie)
			logger.Debug("usdt uprobe not attached",
				zap.Uint32("pid", pid), zap.String("probe", p.Provider+":"+p.Name), zap.Error(err))
			continue
		}
		links = append(links, l)
		logger.Debug("usdt uprobe attached",
			zap.Uint32("pid", pid), zap.String("probe", p.Provider+":"+p.Name),
			zap.Uint64("offset", addr), zap.Bool("semaphore", opts.RefCtrOffset != 0))
	}
	return links
}

// copyCString copies s into dst as a NUL-terminated C string, reserving the
// final byte for the terminator and truncating longer names.
func copyCString(dst []byte, s string) {
	if len(dst) == 0 {
		return
	}
	n := copy(dst[:len(dst)-1], s)
	dst[n] = 0
}

var (
	refCtrOnce      sync.Once
	refCtrSupported bool
)

// uprobeRefCtrOffsetSupported reports whether the kernel exposes SDT semaphore
// (ref_ctr_offset) management for uprobes. Checked once.
func uprobeRefCtrOffsetSupported() bool {
	refCtrOnce.Do(func() {
		_, err := os.Stat("/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset")
		refCtrSupported = err == nil
	})
	return refCtrSupported
}
