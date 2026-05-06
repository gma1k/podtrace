//go:build embed_bpf

package embedded

import "testing"

func TestEmbeddedPodtraceBPFObj_NonEmpty(t *testing.T) {
	if len(EmbeddedPodtraceBPFObj) == 0 {
		t.Fatal("EmbeddedPodtraceBPFObj is empty — likely missing per-arch embed for current GOARCH")
	}
}