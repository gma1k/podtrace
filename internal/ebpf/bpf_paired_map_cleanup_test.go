package ebpf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var pairedLifetimeMaps = []string{"start_times", "syscall_paths", "lock_targets"}

var earlyReturnRe = regexp.MustCompile(`if\s*\([^)]*\)\s*\{[^{}]*?return[^;]*;[^{}]*\}`)

func TestPairedLifetimeMapsAreLRU(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(locateBPFDir(t), "maps.h"))
	if err != nil {
		t.Fatalf("read maps.h: %v", err)
	}
	text := string(src)

	for _, name := range pairedLifetimeMaps {
		end := strings.Index(text, "} "+name+" SEC(")
		if end < 0 {
			t.Errorf("map %q not found in maps.h", name)
			continue
		}
		start := strings.LastIndex(text[:end], "struct {")
		if start < 0 {
			t.Errorf("map %q: no struct opener before its declaration", name)
			continue
		}
		if !strings.Contains(text[start:end], "BPF_MAP_TYPE_LRU_HASH") {
			t.Errorf("map %q must be BPF_MAP_TYPE_LRU_HASH so an entry whose return probe never "+
				"fires (kretprobe miss, thread death) is evicted rather than pinned; a plain HASH "+
				"fills and silently disables every probe sharing it", name)
		}
	}
}

func TestReturnProbesCleanUpPairedMapsOnEarlyReturn(t *testing.T) {
	bpfDir := locateBPFDir(t)

	entries, err := os.ReadDir(bpfDir)
	if err != nil {
		t.Fatalf("read bpf dir %q: %v", bpfDir, err)
	}

	var violations []string
	fnRe := regexp.MustCompile(`\nint\s+(\w+)\s*\([^)]*\)\s*\{`)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".c") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(bpfDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		text := string(src)

		for _, m := range fnRe.FindAllStringSubmatchIndex(text, -1) {
			name := text[m[2]:m[3]]
			body, ok := braceBody(text, m[1]-1)
			if !ok || !strings.Contains(body, "get_event_buf()") {
				continue
			}

			var owned []string
			for _, mp := range pairedLifetimeMaps {
				if strings.Contains(body, "bpf_map_delete_elem(&"+mp+",") {
					owned = append(owned, mp)
				}
			}
			if len(owned) < 2 {
				continue
			}

			for _, blk := range earlyReturnRe.FindAllString(body, -1) {
				cond := strings.TrimSpace(strings.SplitN(blk, "{", 2)[0])
				if strings.Contains(cond, "start_ts") {
					continue
				}
				for _, mp := range owned {
					if !strings.Contains(blk, "bpf_map_delete_elem(&"+mp+",") {
						violations = append(violations,
							e.Name()+":"+name+" early return `"+cond+"` on the consume path leaks "+mp)
					}
				}
			}
		}
	}

	if len(violations) > 0 {
		t.Fatalf("BPF return probes leak paired maps on an early-return path:\n  %s",
			strings.Join(violations, "\n  "))
	}
}

func braceBody(text string, openIdx int) (string, bool) {
	for openIdx < len(text) && text[openIdx] != '{' {
		openIdx++
	}
	if openIdx >= len(text) {
		return "", false
	}
	depth := 0
	for i := openIdx; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return text[openIdx : i+1], true
			}
		}
	}
	return "", false
}

func locateBPFDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			bpfDir := filepath.Join(dir, "bpf")
			if _, err := os.Stat(bpfDir); err != nil {
				t.Fatalf("bpf dir not found at module root %q: %v", dir, err)
			}
			return bpfDir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("module root (go.mod) not found walking up from working directory")
		}
		dir = parent
	}
}
