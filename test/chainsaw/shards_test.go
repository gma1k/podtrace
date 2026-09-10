package chainsaw

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	shardFile = "shards.conf"
	testsDir  = "tests"
)

func readShardAssignment(t *testing.T) map[string]string {
	t.Helper()

	raw, err := os.ReadFile(shardFile)
	if err != nil {
		t.Fatalf("read %s: %v", shardFile, err)
	}

	assigned := map[string]string{}
	for i, entry := range strings.Split(string(raw), "\n") {
		line := i + 1
		text := strings.TrimSpace(entry)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 2 {
			t.Fatalf("%s:%d: want '<shard> <test-name>', got %q", shardFile, line, text)
		}
		shard, name := fields[0], fields[1]
		if prev, dup := assigned[name]; dup {
			t.Errorf("%s:%d: %q is assigned to shard %s and shard %s; a test that runs "+
				"twice wastes a shard's budget and can collide with itself over the "+
				"shared TracerConfig", shardFile, line, name, prev, shard)
			continue
		}
		assigned[name] = shard
	}
	return assigned
}

func discoverTests(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(testsDir)
	if err != nil {
		t.Fatalf("read %s: %v", testsDir, err)
	}

	var found []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		manifest := filepath.Join(testsDir, e.Name(), "chainsaw-test.yaml")
		if _, err := os.Stat(manifest); err != nil {
			continue
		}
		found = append(found, e.Name())
	}
	sort.Strings(found)
	return found
}

func TestEveryChainsawTestIsAssignedToExactlyOneShard(t *testing.T) {
	assigned := readShardAssignment(t)
	found := discoverTests(t)

	if len(found) == 0 {
		t.Fatalf("no chainsaw tests discovered under %s/", testsDir)
	}

	for _, name := range found {
		if _, ok := assigned[name]; !ok {
			t.Errorf("chainsaw test %q is in %s/ but not in %s.\n\nThe e2e matrix runs "+
				"explicit per-shard test lists, so an unassigned test is silently never "+
				"executed and CI stays green while its coverage is gone. Add it to a "+
				"shard.", name, testsDir, shardFile)
		}
	}
}

func TestNoShardReferencesAMissingTest(t *testing.T) {
	assigned := readShardAssignment(t)
	found := discoverTests(t)

	exists := make(map[string]bool, len(found))
	for _, name := range found {
		exists[name] = true
	}

	for name, shard := range assigned {
		if !exists[name] {
			t.Errorf("%s assigns %q to shard %s, but %s/%s/chainsaw-test.yaml does not "+
				"exist; the shard's chainsaw invocation will fail to load it",
				shardFile, name, shard, testsDir, name)
		}
	}
}

func TestShardsAreContiguouslyNumberedFromOne(t *testing.T) {
	assigned := readShardAssignment(t)

	seen := map[string]bool{}
	for _, shard := range assigned {
		seen[shard] = true
	}

	for i := 1; i <= len(seen); i++ {
		want := strconv.Itoa(i)
		if !seen[want] {
			t.Errorf("shard %s is empty but shard count is %d. The workflow matrix "+
				"enumerates 1..N, so a gap means one matrix job runs nothing while "+
				"another job's tests go unassigned.", want, len(seen))
		}
	}
}
