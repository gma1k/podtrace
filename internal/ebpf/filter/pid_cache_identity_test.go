package filter

import (
	"testing"
	"time"
)

func stubStartTicks(t *testing.T, fn func(uint32) (uint64, bool)) {
	t.Helper()
	orig := processStartTicks
	processStartTicks = fn
	t.Cleanup(func() { processStartTicks = orig })
}

func stubCgroupFile(t *testing.T, content *string, reads *int) {
	t.Helper()
	orig := readFile
	readFile = func(string) ([]byte, error) {
		if reads != nil {
			*reads++
		}
		return []byte(*content), nil
	}
	t.Cleanup(func() { readFile = orig })
}

func TestAReusedPIDDoesNotInheritACachedAdmission(t *testing.T) {
	start := uint64(100)
	stubStartTicks(t, func(uint32) (uint64, bool) { return start, true })
	content := "0::/kubepods/podA"
	stubCgroupFile(t, &content, nil)

	f := NewCgroupFilter()
	f.SetCgroupPath("/kubepods/podA")
	f.ttl = time.Minute

	if !f.IsPIDInCgroup(4242) {
		t.Fatal("a process in the target cgroup was refused")
	}

	start = 200
	content = "0::/kubepods/podB"
	if f.IsPIDInCgroup(4242) {
		t.Fatal("a new process that reused a targeted pid was admitted from the cache")
	}
}

func TestACachedAdmissionIsReusedWhileTheSameProcessHoldsThePID(t *testing.T) {
	stubStartTicks(t, func(uint32) (uint64, bool) { return 100, true })
	content := "0::/kubepods/podA"
	reads := 0
	stubCgroupFile(t, &content, &reads)

	f := NewCgroupFilter()
	f.SetCgroupPath("/kubepods/podA")
	f.ttl = time.Minute

	f.IsPIDInCgroup(4242)
	f.IsPIDInCgroup(4242)
	if reads != 1 {
		t.Fatalf("cgroup file read %d times, want 1", reads)
	}
}

func TestAnAdmissionIsNotCachedWhenTheProcessCannotBeIdentified(t *testing.T) {
	stubStartTicks(t, func(uint32) (uint64, bool) { return 0, false })
	content := "0::/kubepods/podA"
	stubCgroupFile(t, &content, nil)

	f := NewCgroupFilter()
	f.SetCgroupPath("/kubepods/podA")
	f.ttl = time.Minute

	if !f.IsPIDInCgroup(4242) {
		t.Fatal("a process in the target cgroup was refused")
	}
	content = "0::/kubepods/podB"
	if f.IsPIDInCgroup(4242) {
		t.Fatal("an admission was served from the cache without knowing which process earned it")
	}
}

func TestARefusalIsCachedOnThePIDAlone(t *testing.T) {
	start := uint64(100)
	stubStartTicks(t, func(uint32) (uint64, bool) { return start, true })
	content := "0::/kubepods/podB"
	reads := 0
	stubCgroupFile(t, &content, &reads)

	f := NewCgroupFilter()
	f.SetCgroupPath("/kubepods/podA")
	f.ttl = time.Minute

	f.IsPIDInCgroup(4242)
	start = 200
	f.IsPIDInCgroup(4242)
	if reads != 1 {
		t.Fatalf("cgroup file read %d times, want 1", reads)
	}
}

func TestAVerdictComputedAgainstOldTargetsIsNotCached(t *testing.T) {
	stubStartTicks(t, func(uint32) (uint64, bool) { return 100, true })
	f := NewCgroupFilter()
	f.SetCgroupPath("/kubepods/podA")
	f.ttl = time.Minute

	orig := readFile
	readFile = func(string) ([]byte, error) {
		f.SetCgroupPaths([]string{"/kubepods/podC"})
		return []byte("0::/kubepods/podA"), nil
	}
	t.Cleanup(func() { readFile = orig })

	if !f.IsPIDInCgroup(4242) {
		t.Fatal("the in-flight lookup should answer against the targets it started with")
	}

	content := "0::/kubepods/podA"
	stubCgroupFile(t, &content, nil)
	if f.IsPIDInCgroup(4242) {
		t.Fatal("an admission computed against withdrawn targets was cached and reused")
	}
}

func TestAVerdictFromAnOlderGenerationIsIgnored(t *testing.T) {
	stubStartTicks(t, func(uint32) (uint64, bool) { return 100, true })
	f := NewCgroupFilter()
	f.SetCgroupPath("/kubepods/podA")
	f.ttl = time.Minute
	f.pidCache[4242] = pidCacheEntry{result: true, at: time.Now(), generation: f.generation.Load() - 1, startTicks: 100}

	content := "0::/kubepods/podB"
	stubCgroupFile(t, &content, nil)
	if f.IsPIDInCgroup(4242) {
		t.Fatal("a cached admission from an earlier target set was served")
	}
}
