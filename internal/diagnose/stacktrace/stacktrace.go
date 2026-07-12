package stacktrace

import (
	"context"
	"debug/elf"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/hostfs"
	"github.com/podtrace/podtrace/internal/procfs"
	"github.com/podtrace/podtrace/internal/safeconv"
)

type Diagnostician interface {
	GetEvents() []*events.Event
}

type stackSummary struct {
	Key        string
	Count      int
	Sample     *events.Event
	FirstFrame string
}

type stackResolver struct {
	cache    map[string]string
	segments map[string][]loadSegment
	mappings map[string][]exeMapping
}

// loadSegment is a PT_LOAD program header: the file-offset range it covers and
// the virtual address it loads at in the ELF's own (unbiased) address space.
type loadSegment struct {
	off    uint64
	vaddr  uint64
	filesz uint64
}

// exeMapping is one file-backed line from /proc/<pid>/maps: the runtime address
// range and the file offset at its start.
type exeMapping struct {
	start uint64
	end   uint64
	pgoff uint64
}

func (r *stackResolver) resolve(ctx context.Context, pid uint32, addr uint64) string {
	select {
	case <-ctx.Done():
		return ""
	default:
	}

	if addr == 0 {
		return ""
	}
	if r.cache == nil {
		r.cache = make(map[string]string)
	}
	if IsKernelAddress(addr) {
		if sym := defaultKallsyms.Resolve(addr); sym != "" {
			return sym
		}
		return fmt.Sprintf("0x%x", addr)
	}
	exePath, err := procfs.Readlink(fmt.Sprintf("%d/exe", pid))
	if err != nil || exePath == "" {
		return fmt.Sprintf("0x%x", addr)
	}
	if _, err := hostfs.Stat(exePath); err != nil {
		return fmt.Sprintf("0x%x", addr)
	}
	key := exePath + "|" + fmt.Sprintf("%x", addr)
	if v, ok := r.cache[key]; ok {
		return v
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, config.DefaultAddr2lineTimeout)
	defer cancel()
	addr2lineBin, err := exec.LookPath("addr2line")
	if err != nil {
		v := fmt.Sprintf("%s@0x%x", filepath.Base(exePath), addr)
		r.cache[key] = v
		return v
	}
	symAddr := addr
	if v, ok := r.translateAddr(pid, exePath, addr); ok {
		symAddr = v
	}
	cmd := exec.CommandContext(timeoutCtx, addr2lineBin, "-e", exePath, fmt.Sprintf("%#x", symAddr)) // #nosec G204 -- LookPath-resolved binary; exePath validated via hostfs.Stat; address is %#x-formatted
	out, err := cmd.Output()
	if err != nil {
		v := fmt.Sprintf("%s@0x%x", filepath.Base(exePath), addr)
		r.cache[key] = v
		return v
	}
	line := strings.TrimSpace(string(out))
	if line == "" || line == "??:0" || line == "??:?" {
		line = fmt.Sprintf("%s@0x%x", filepath.Base(exePath), addr)
	} else {
		line = filepath.Base(exePath) + ":" + line
	}
	r.cache[key] = line
	return line
}

// translateAddr converts a runtime instruction pointer into the ELF virtual
// address addr2line expects.
func (r *stackResolver) translateAddr(pid uint32, exePath string, addr uint64) (uint64, bool) {
	mappings := r.exeMappings(pid, exePath)
	var fileOffset uint64
	found := false
	for _, m := range mappings {
		if addr >= m.start && addr < m.end {
			fileOffset = addr - m.start + m.pgoff
			found = true
			break
		}
	}
	if !found {
		return 0, false
	}

	for _, s := range r.loadSegments(exePath) {
		if fileOffset >= s.off && fileOffset < s.off+s.filesz {
			return fileOffset - s.off + s.vaddr, true
		}
	}
	return 0, false
}

// exeMappings returns the file-backed mappings of exePath in process pid,
// parsed from /proc/<pid>/maps and cached per (pid, exePath).
func (r *stackResolver) exeMappings(pid uint32, exePath string) []exeMapping {
	if r.mappings == nil {
		r.mappings = make(map[string][]exeMapping)
	}
	key := fmt.Sprintf("%d|%s", pid, exePath)
	if m, ok := r.mappings[key]; ok {
		return m
	}

	var out []exeMapping
	data, err := procfs.ReadFile(fmt.Sprintf("%d/maps", pid))
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			if strings.Join(fields[5:], " ") != exePath {
				continue
			}
			dash := strings.IndexByte(fields[0], '-')
			if dash < 0 {
				continue
			}
			start, err1 := strconv.ParseUint(fields[0][:dash], 16, 64)
			end, err2 := strconv.ParseUint(fields[0][dash+1:], 16, 64)
			pgoff, err3 := strconv.ParseUint(fields[2], 16, 64)
			if err1 != nil || err2 != nil || err3 != nil {
				continue
			}
			out = append(out, exeMapping{start: start, end: end, pgoff: pgoff})
		}
	}
	r.mappings[key] = out
	return out
}

// loadSegments returns exePath's PT_LOAD program headers, parsing the ELF once
// and caching the result.
func (r *stackResolver) loadSegments(exePath string) []loadSegment {
	if r.segments == nil {
		r.segments = make(map[string][]loadSegment)
	}
	if s, ok := r.segments[exePath]; ok {
		return s
	}

	var out []loadSegment
	if f, err := hostfs.Open(exePath); err == nil {
		if ef, eerr := elf.NewFile(f); eerr == nil {
			for _, p := range ef.Progs {
				if p.Type == elf.PT_LOAD {
					out = append(out, loadSegment{off: p.Off, vaddr: p.Vaddr, filesz: p.Filesz})
				}
			}
		}
		_ = f.Close()
	}
	r.segments[exePath] = out
	return out
}

func GenerateStackTraceSectionWithContext(d Diagnostician, ctx context.Context) string {
	allEvents := d.GetEvents()
	if len(allEvents) == 0 {
		return ""
	}

	resolver := &stackResolver{cache: make(map[string]string)}
	stackMap := make(map[string]*stackSummary)
	processed := 0

	for _, e := range allEvents {
		if processed >= config.MaxEventsForStacks {
			break
		}
		if e == nil {
			continue
		}
		if len(e.Stack) == 0 {
			continue
		}
		if e.LatencyNS < safeconv.Int64ToUint64(config.MinLatencyForStackNS) && e.Type != events.EventLockContention && e.Type != events.EventDBQuery {
			continue
		}
		processed++
		top := e.Stack[0]
		frame := resolver.resolve(ctx, e.PID, top)
		if frame == "" {
			continue
		}
		key := fmt.Sprintf("%s|%d", frame, e.Type)
		if entry, ok := stackMap[key]; ok {
			entry.Count++
		} else {
			stackMap[key] = &stackSummary{
				Key:        key,
				Count:      1,
				Sample:     e,
				FirstFrame: frame,
			}
		}
	}

	if len(stackMap) == 0 {
		return ""
	}

	var summaries []*stackSummary
	for _, v := range stackMap {
		summaries = append(summaries, v)
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Count > summaries[j].Count
	})

	var report string
	report += "Stack Traces for Slow Operations:\n"
	limit := config.MaxStackTracesLimit
	if len(summaries) < limit {
		limit = len(summaries)
	}
	for i := 0; i < limit; i++ {
		s := summaries[i]
		e := s.Sample
		if e == nil {
			continue
		}
		if e.Target != "" {
			report += fmt.Sprintf("  Hot stack %d: %d events, type=%s, target=%s, avg latency=%.2fms\n", i+1, s.Count, e.TypeString(), e.Target, float64(e.LatencyNS)/float64(config.NSPerMS))
		} else {
			report += fmt.Sprintf("  Hot stack %d: %d events, type=%s, avg latency=%.2fms\n", i+1, s.Count, e.TypeString(), float64(e.LatencyNS)/float64(config.NSPerMS))
		}
		maxFrames := config.MaxStackFramesLimit
		if len(e.Stack) < maxFrames {
			maxFrames = len(e.Stack)
		}
		for j := 0; j < maxFrames; j++ {
			addr := e.Stack[j]
			frame := resolver.resolve(ctx, e.PID, addr)
			report += fmt.Sprintf("    #%d %s\n", j, frame)
		}
	}
	report += "\n"
	return report
}
