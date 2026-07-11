package tracer

import (
	"testing"

	"github.com/podtrace/podtrace/internal/ebpf/filter"
)

func TestSetContainerIDs_AttachesPerContainer(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}

	if err := tr.SetContainerIDs([]string{"containeraaaa", "containerbbbb"}); err != nil {
		t.Fatalf("SetContainerIDs: %v", err)
	}

	if got := len(tr.containerUprobes); got != 2 {
		t.Fatalf("expected a per-container uprobe set for each of 2 containers, got %d", got)
	}
	for _, id := range []string{"containeraaaa", "containerbbbb"} {
		if _, ok := tr.containerUprobes[id]; !ok {
			t.Errorf("missing per-container uprobe set for %q", id)
		}
	}
}

func TestSetContainerIDs_DedupesAndSkipsEmpty(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}

	if err := tr.SetContainerIDs([]string{"containeraaaa", "", "containeraaaa"}); err != nil {
		t.Fatalf("SetContainerIDs: %v", err)
	}
	if got := len(tr.containerUprobes); got != 1 {
		t.Fatalf("expected 1 deduplicated container, got %d", got)
	}
}

func TestSetContainerIDs_AllEmptyErrors(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}
	if err := tr.SetContainerIDs([]string{"", ""}); err == nil {
		t.Fatal("expected error for all-empty container IDs")
	}
}
