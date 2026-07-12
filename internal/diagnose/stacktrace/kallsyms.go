package stacktrace

import (
	"bufio"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/procfs"
)

// kallsymsLookup loads /proc/kallsyms once and resolves kernel addresses to
// symbol names.
type kallsymsLookup struct {
	once    sync.Once
	syms    []ksym
	loaded  bool
	maxAddr uint64
}

type ksym struct {
	Addr uint64
	Name string
}

var defaultKallsyms = &kallsymsLookup{}

func (k *kallsymsLookup) load() {
	f, err := procfs.Open("kallsyms")
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil || addr == 0 {
			continue
		}
		k.syms = append(k.syms, ksym{Addr: addr, Name: parts[2]})
		if addr > k.maxAddr {
			k.maxAddr = addr
		}
	}
	if err := scanner.Err(); err != nil {
		logger.Warn("Kernel symbol table read was truncated; some kernel stack frames may show as raw hex", zap.Error(err))
	}
	if !isSorted(k.syms) {
		sortKsyms(k.syms)
	}
	k.loaded = len(k.syms) > 0
	if !k.loaded {
		logger.Warn("Kernel symbol resolution unavailable: /proc/kallsyms returned no addresses (kernel.kptr_restrict is non-zero). Stack frames at kernel addresses will display as raw hex. Set kernel.kptr_restrict=0 on the node to enable symbolication.")
	}
}

// Resolve returns "<symbol>+0x<offset>" for kernel address addr, or "" when
// kallsyms is unavailable or the address falls outside the symbol table.
func (k *kallsymsLookup) Resolve(addr uint64) string {
	k.once.Do(k.load)
	if !k.loaded || addr == 0 || addr > k.maxAddr {
		return ""
	}
	lo, hi := 0, len(k.syms)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		if k.syms[mid].Addr <= addr {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if hi < 0 {
		return ""
	}
	s := k.syms[hi]
	return s.Name + "+0x" + strconv.FormatUint(addr-s.Addr, 16)
}

// IsKernelAddress is a fast heuristic: x86_64 and arm64 kernel virtual
// addresses live above 0xffff800000000000. User addresses are below.
func IsKernelAddress(addr uint64) bool {
	return addr >= 0xffff800000000000
}

func isSorted(s []ksym) bool {
	for i := 1; i < len(s); i++ {
		if s[i].Addr < s[i-1].Addr {
			return false
		}
	}
	return true
}

func sortKsyms(s []ksym) {
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j].Addr < s[j-1].Addr {
			s[j], s[j-1] = s[j-1], s[j]
			j--
		}
	}
}
