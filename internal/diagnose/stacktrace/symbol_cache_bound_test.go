package stacktrace

import (
	"os"
	"path/filepath"
	"testing"
)

type fakeFS struct {
	ids   map[string]fileID
	loads map[string]int
}

func newFakeFS(ids map[string]fileID) *fakeFS {
	return &fakeFS{ids: ids, loads: map[string]int{}}
}

func (f *fakeFS) cache() *symbolTableCache {
	return &symbolTableCache{
		limit: 2,
		statID: func(path string) (fileID, bool) {
			id, ok := f.ids[path]
			return id, ok
		},
		load: func(path string) *symbolTable {
			f.loads[path]++
			return &symbolTable{}
		},
	}
}

func (f *fakeFS) totalLoads() int {
	n := 0
	for _, c := range f.loads {
		n += c
	}
	return n
}

func TestTheSameBinaryUnderManyPIDsIsParsedOnce(t *testing.T) {
	same := fileID{dev: 1, ino: 42}
	fs := newFakeFS(map[string]fileID{
		"/host/proc/100/root/usr/bin/app": same,
		"/host/proc/200/root/usr/bin/app": same,
		"/host/proc/300/root/usr/bin/app": same,
	})
	c := fs.cache()

	for _, p := range []string{
		"/host/proc/100/root/usr/bin/app",
		"/host/proc/200/root/usr/bin/app",
		"/host/proc/300/root/usr/bin/app",
	} {
		c.get(p)
	}

	if got := fs.totalLoads(); got != 1 {
		t.Errorf("parsed the same executable %d times across three PIDs, want 1.\n\n"+
			"Paths carry the PID, so keying on the path reparsed and cached the whole "+
			"table once per process. One table for a large Go binary retains over 100 "+
			"MiB of heap; that is how an agent reached its 1 GiB limit and was "+
			"OOM-killed.", got)
	}
	if got := c.len(); got != 1 {
		t.Errorf("held %d entries for one executable, want 1", got)
	}
}

func TestTheCacheNeverHoldsMoreThanItsBound(t *testing.T) {
	ids := map[string]fileID{}
	var paths []string
	for i := 0; i < 10; i++ {
		p := filepath.Join("/bin", string(rune('a'+i)))
		ids[p] = fileID{dev: 1, ino: uint64(100 + i)}
		paths = append(paths, p)
	}
	c := newFakeFS(ids).cache()

	for _, p := range paths {
		c.get(p)
		if got := c.len(); got > c.limit {
			t.Fatalf("held %d tables after %s, bound is %d", got, p, c.limit)
		}
	}
}

func TestTheLeastRecentlyUsedTableIsEvictedFirst(t *testing.T) {
	fs := newFakeFS(map[string]fileID{
		"/bin/a": {dev: 1, ino: 1},
		"/bin/b": {dev: 1, ino: 2},
		"/bin/c": {dev: 1, ino: 3},
	})
	c := fs.cache()

	c.get("/bin/a")
	c.get("/bin/b")
	c.get("/bin/a")
	c.get("/bin/c")

	c.get("/bin/a")
	if fs.loads["/bin/a"] != 1 {
		t.Errorf("/bin/a was reloaded %d times; it was the most recently used when "+
			"/bin/c arrived and should have survived", fs.loads["/bin/a"])
	}
	c.get("/bin/b")
	if fs.loads["/bin/b"] != 2 {
		t.Errorf("/bin/b loaded %d times, want 2: it was least recently used and "+
			"should have been evicted", fs.loads["/bin/b"])
	}
}

func TestAnEvictedTableIsReloadedCorrectly(t *testing.T) {
	fs := newFakeFS(map[string]fileID{
		"/bin/a": {dev: 1, ino: 1},
		"/bin/b": {dev: 1, ino: 2},
		"/bin/c": {dev: 1, ino: 3},
	})
	c := fs.cache()

	first := c.get("/bin/a")
	c.get("/bin/b")
	c.get("/bin/c")
	again := c.get("/bin/a")

	if first == nil || again == nil {
		t.Fatal("a table came back nil")
	}
	if fs.loads["/bin/a"] != 2 {
		t.Errorf("/bin/a loaded %d times, want 2 after eviction", fs.loads["/bin/a"])
	}
}

func TestSameInodeOnDifferentDevicesIsNotConfused(t *testing.T) {
	fs := newFakeFS(map[string]fileID{
		"/mnt/one/app": {dev: 1, ino: 7},
		"/mnt/two/app": {dev: 2, ino: 7},
	})
	c := fs.cache()

	c.get("/mnt/one/app")
	c.get("/mnt/two/app")

	if got := fs.totalLoads(); got != 2 {
		t.Errorf("parsed %d times for two files sharing an inode number on different "+
			"devices, want 2; they are different executables", got)
	}
}

func TestAnUnstattableExecutableIsResolvedButNotCached(t *testing.T) {
	fs := newFakeFS(map[string]fileID{})
	c := fs.cache()

	if c.get("/gone/app") == nil {
		t.Fatal("an executable that cannot be stat'd was not resolved at all")
	}
	c.get("/gone/app")
	if got := c.len(); got != 0 {
		t.Errorf("cached %d entries with no identity to key on, want 0", got)
	}
	if fs.loads["/gone/app"] != 2 {
		t.Errorf("loads = %d, want 2: with no key it cannot be reused", fs.loads["/gone/app"])
	}
}

func TestARealFileSeenThroughTwoPathsSharesOneEntry(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "app")
	if err := os.WriteFile(real, []byte("not an elf"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Link(real, alias); err != nil {
		t.Skipf("hardlinks unsupported here: %v", err)
	}

	id1, ok1 := statFileID(real)
	id2, ok2 := statFileID(alias)
	if !ok1 || !ok2 {
		t.Fatalf("statFileID failed: %v %v", ok1, ok2)
	}
	if id1 != id2 {
		t.Errorf("a hardlink reported a different identity: %+v vs %+v", id1, id2)
	}
}

func TestStatFileIDRejectsAMissingPath(t *testing.T) {
	if _, ok := statFileID(filepath.Join(t.TempDir(), "nope")); ok {
		t.Error("statFileID reported an identity for a path that does not exist")
	}
}
