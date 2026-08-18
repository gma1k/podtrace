package filter

import (
	"testing"
	"time"
)

func TestPIDCache_TTLInvalidatesReusedPID(t *testing.T) {
	origReadFile := readFile
	defer func() { readFile = origReadFile }()

	f := NewCgroupFilter()
	f.SetCgroupPath("/kubepods/podA")
	base := time.Unix(1_000_000, 0)
	now := base
	f.now = func() time.Time { return now }
	f.ttl = 30 * time.Second

	readFile = func(string) ([]byte, error) { return []byte("0::/kubepods/podA"), nil }
	if !f.IsPIDInCgroup(4242) {
		t.Fatal("PID initially in the target cgroup must be admitted")
	}

	readFile = func(string) ([]byte, error) { return []byte("0::/kubepods/podB"), nil }
	if !f.IsPIDInCgroup(4242) {
		t.Fatal("within TTL the cached decision applies (a cache hit is expected)")
	}

	now = base.Add(31 * time.Second)
	if f.IsPIDInCgroup(4242) {
		t.Fatal("after TTL a reused PID must be re-evaluated and denied (no cross-tenant leak)")
	}
}

func TestPIDCache_WithinTTLServesFromCache(t *testing.T) {
	origReadFile := readFile
	defer func() { readFile = origReadFile }()

	f := NewCgroupFilter()
	f.SetCgroupPath("/kubepods/podA")
	now := time.Unix(2_000_000, 0)
	f.now = func() time.Time { return now }
	f.ttl = 30 * time.Second

	reads := 0
	readFile = func(string) ([]byte, error) {
		reads++
		return []byte("0::/kubepods/podA"), nil
	}
	f.IsPIDInCgroup(7777)
	now = now.Add(5 * time.Second)
	f.IsPIDInCgroup(7777)
	if reads != 1 {
		t.Fatalf("within TTL the /proc read must not repeat, got %d reads", reads)
	}
}
