package agent

import "testing"

// TestIdentifyContainerCgroup_DeterministicOnSharedPrefix guards the fix for
// the bidirectional-HasPrefix mis-association: when several container IDs share
// a prefix with the cgroup dir, the match must be the longest (most specific),
// tie-broken lexicographically, and stable across map iteration order.
func TestIdentifyContainerCgroup_DeterministicOnSharedPrefix(t *testing.T) {
	// "aaaa" prefixes both; the longer ID wins.
	longest := map[string]string{
		"aaaabbbb":     "short",
		"aaaabbbbcccc": "long",
	}
	// Same length: lexicographically-first wins.
	tie := map[string]string{
		"aaaa2222": "b",
		"aaaa1111": "a",
	}

	for i := 0; i < 30; i++ {
		if name, id := identifyContainerCgroup("docker-aaaa.scope", longest); id != "aaaabbbbcccc" || name != "long" {
			t.Fatalf("longest-match iter %d: got (%q,%q), want (long, aaaabbbbcccc)", i, name, id)
		}
		if name, id := identifyContainerCgroup("docker-aaaa.scope", tie); id != "aaaa1111" || name != "a" {
			t.Fatalf("tie-break iter %d: got (%q,%q), want (a, aaaa1111)", i, name, id)
		}
	}
}
