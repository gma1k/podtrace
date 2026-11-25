package main

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/storagemigrate"
)

func TestFormatResultReportsDeletedAndConflictingObjects(t *testing.T) {
	line := formatResult(storagemigrate.Result{
		CRD:            "widgets.podtrace.io",
		StorageVersion: "v1beta1",
		Objects:        5,
		Rewritten:      3,
		Deleted:        1,
		Conflicts:      1,
		Unpinned:       []string{"v1alpha1"},
	}, false)
	for _, want := range []string{"rewrote 3", "1 deleted meanwhile", "1 changed under us", "unpinned v1alpha1"} {
		if !strings.Contains(line, want) {
			t.Errorf("formatResult = %q, missing %q", line, want)
		}
	}
}

func TestFormatResultOmitsDeletedWhenNoneWere(t *testing.T) {
	line := formatResult(storagemigrate.Result{CRD: "widgets.podtrace.io", StorageVersion: "v1beta1", Objects: 2, Rewritten: 2}, false)
	if strings.Contains(line, "deleted") {
		t.Errorf("formatResult = %q, want no deleted count", line)
	}
}
