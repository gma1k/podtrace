package tracer

import (
	"runtime/debug"
	"testing"
)

func TestTheObjectLoadsUnderATighterCollectorAndPutsItBack(t *testing.T) {
	before := debug.SetGCPercent(80)
	defer debug.SetGCPercent(before)

	restore := tightGCForLoad()
	if during := debug.SetGCPercent(loadGCPercent); during != loadGCPercent {
		t.Errorf("GOGC during the load = %d, want %d", during, loadGCPercent)
	}
	restore()
	if after := debug.SetGCPercent(80); after != 80 {
		t.Errorf("GOGC after the load = %d, want the 80 it was", after)
	}
}
