package loader

import (
	"os"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func loadSpecOrSkip(t *testing.T) (programs, maps map[string]struct{}) {
	t.Helper()
	originalPath := config.BPFObjectPath
	t.Cleanup(func() { config.BPFObjectPath = originalPath })

	config.BPFObjectPath = findBPFObjectPath()

	spec, err := LoadPodtrace()
	if err != nil {
		t.Skipf("BPF object not built in this environment (run: make internal/ebpf/embedded/podtrace.$GOARCH.bpf.o): %v", err)
	}
	if spec == nil {
		t.Fatal("LoadPodtrace returned nil spec without error")
	}

	programs = make(map[string]struct{}, len(spec.Programs))
	for name := range spec.Programs {
		programs[name] = struct{}{}
	}
	maps = make(map[string]struct{}, len(spec.Maps))
	for name := range spec.Maps {
		maps[name] = struct{}{}
	}
	return programs, maps
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func findBPFObjectPath() string {
	rel := config.DefaultBPFObjectPath()
	prefix := ""
	for i := 0; i < 6; i++ {
		if fileExists(prefix + rel) {
			return prefix + rel
		}
		prefix += "../"
	}
	return rel
}

func TestLoadedSpec_HasCoreProgramsAndMaps(t *testing.T) {
	programs, maps := loadSpecOrSkip(t)

	corePrograms := []string{"dns_egress", "dns_ingress", "kprobe_tcp_connect"}
	for _, name := range corePrograms {
		if _, ok := programs[name]; !ok {
			t.Errorf("compiled BPF object is missing core program %q (a stub/truncated build?)", name)
		}
	}

	coreMaps := []string{"events", "stack_traces", "target_cgroup_ids"}
	for _, name := range coreMaps {
		if _, ok := maps[name]; !ok {
			t.Errorf("compiled BPF object is missing core map %q (a stub/truncated build?)", name)
		}
	}
}

func TestLoadedSpec_HasHealthyProgramAndMapCounts(t *testing.T) {
	programs, maps := loadSpecOrSkip(t)

	const minPrograms = 10
	const minMaps = 10
	if len(programs) < minPrograms {
		t.Errorf("compiled BPF object has %d programs, want >= %d (truncated build?)", len(programs), minPrograms)
	}
	if len(maps) < minMaps {
		t.Errorf("compiled BPF object has %d maps, want >= %d (truncated build?)", len(maps), minMaps)
	}
}
