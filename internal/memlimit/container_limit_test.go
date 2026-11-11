package memlimit

import "testing"

func TestContainerLimitPrefersTheDownwardAPI(t *testing.T) {
	limitEnv = "268435456"
	t.Cleanup(func() { limitEnv = "" })
	withFiles(t, "1073741824\n", "", "")
	if got, ok := ContainerLimit(); !ok || got != 256<<20 {
		t.Errorf("ContainerLimit = %d, %v; want the downward API's 256 MiB", got, ok)
	}
}

func TestContainerLimitReadsTheCgroup(t *testing.T) {
	withFiles(t, "1073741824\n", "", "")
	if got, ok := ContainerLimit(); !ok || got != 1<<30 {
		t.Errorf("ContainerLimit = %d, %v; want the cgroup's 1 GiB", got, ok)
	}
}

func TestContainerLimitReportsNoneWhenUnlimited(t *testing.T) {
	withFiles(t, "max\n", "", "")
	if got, ok := ContainerLimit(); ok {
		t.Errorf("ContainerLimit = %d, want none for an unlimited cgroup", got)
	}
}
