package resource

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkingSetSubtractsTheInactiveFileCache(t *testing.T) {
	stat := "anon 104857600\nfile 943718400\ninactive_file 838860800\nactive_file 104857600\n"
	cases := []struct {
		name  string
		usage uint64
		stat  string
		key   string
		want  uint64
	}{
		{"page cache excluded", 1048576000, stat, "inactive_file", 209715200},
		{"cache larger than usage floors at zero", 1000, stat, "inactive_file", 0},
		{"missing key keeps usage", 5000, stat, "total_inactive_file", 5000},
		{"unreadable stat keeps usage", 5000, "", "inactive_file", 5000},
		{"malformed value keeps usage", 5000, "inactive_file lots\n", "inactive_file", 5000},
		{"v1 hierarchical key", 3000, "inactive_file 9\ntotal_inactive_file 1000\n", "total_inactive_file", 2000},
	}
	for _, tc := range cases {
		if got := workingSetBytes(tc.usage, tc.stat, tc.key); got != tc.want {
			t.Errorf("%s: workingSetBytes = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestV2MemoryUsageIsTheWorkingSet(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	files := map[string]string{
		"memory.max":     "1073741824",
		"memory.current": "1006632960",
		"memory.stat":    "anon 104857600\ninactive_file 805306368\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(rm.cgroupPath, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rm.refreshLimits()
	rm.mu.Lock()
	err := rm.updateUsageV2()
	usage := rm.limits[ResourceMemory].UsageBytes
	rm.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if usage != 201326592 {
		t.Fatalf("memory usage = %d, want the 192MiB working set rather than the 960MiB that counts page cache", usage)
	}
}

func TestV1MemoryUsageIsTheWorkingSet(t *testing.T) {
	base := t.TempDir()
	useCgroupBase(t, base)
	subpath := "kubepods/pod1"
	cgroupPath := writeCgroupV1Layout(t, base, subpath, map[string]map[string]string{
		"memory": {
			"memory.limit_in_bytes": "1073741824",
			"memory.usage_in_bytes": "1006632960",
			"memory.stat":           "cache 900000000\ninactive_file 1\ntotal_inactive_file 805306368\n",
		},
	})
	rm, err := NewResourceMonitor(cgroupPath, nil, nil, nil, "test-ns")
	if err != nil {
		t.Fatal(err)
	}
	rm.mu.Lock()
	err = rm.updateUsageV1()
	usage := rm.limits[ResourceMemory].UsageBytes
	rm.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if usage != 201326592 {
		t.Fatalf("memory usage = %d, want usage less total_inactive_file", usage)
	}
}
