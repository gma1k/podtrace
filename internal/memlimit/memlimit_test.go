package memlimit

import (
	"os"
	"path/filepath"
	"testing"
)

func withFiles(t *testing.T, v2, v1 string, env string) *int64 {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		if content == "" {
			return
		}
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	origRoot, origSet, origEnv := cgroupRoot, setLimit, getenv
	t.Cleanup(func() { cgroupRoot, setLimit, getenv = origRoot, origSet, origEnv })
	cgroupRoot = dir
	write(cgroupV2Limit, v2)
	write(cgroupV1Limit, v1)
	set := new(int64)
	*set = -1
	setLimit = func(n int64) int64 { *set = n; return 0 }
	getenv = func(key string) string {
		if key == "GOMEMLIMIT" {
			return env
		}
		return ""
	}
	return set
}

func TestACgroupV2LimitBecomesTheGoSoftLimit(t *testing.T) {
	set := withFiles(t, "536870912\n", "", "")
	if got := Apply(); got != 375809638 || *set != got {
		t.Errorf("Apply = %d, set %d; want 70%% of 512 MiB", got, *set)
	}
}

func TestACgroupV1LimitIsUsedWhenThereIsNoV2File(t *testing.T) {
	set := withFiles(t, "", "1073741824\n", "")
	if got := Apply(); got != 751619276 || *set != got {
		t.Errorf("Apply = %d, set %d; want 70%% of 1 GiB", got, *set)
	}
}

func TestNoLimitSetsNothing(t *testing.T) {
	for name, files := range map[string][2]string{
		"v2 max":       {"max\n", ""},
		"v1 unlimited": {"", "9223372036854771712\n"},
		"no files":     {"", ""},
		"unparseable":  {"lots\n", ""},
		"zero":         {"0\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			set := withFiles(t, files[0], files[1], "")
			if got := Apply(); got != 0 || *set != -1 {
				t.Errorf("Apply = %d, set %d; want nothing set", got, *set)
			}
		})
	}
}

func TestNoCgroupFilesystemSetsNothing(t *testing.T) {
	set := withFiles(t, "", "", "")
	cgroupRoot = filepath.Join(cgroupRoot, "absent")
	if got := Apply(); got != 0 || *set != -1 {
		t.Errorf("Apply = %d, set %d; want nothing set", got, *set)
	}
}

func TestAGOMEMLIMITTheUserSetIsLeftAlone(t *testing.T) {
	set := withFiles(t, "536870912\n", "", "300MiB")
	if got := Apply(); got != 0 || *set != -1 {
		t.Errorf("Apply = %d, set %d; the runtime already applied GOMEMLIMIT", got, *set)
	}
}
