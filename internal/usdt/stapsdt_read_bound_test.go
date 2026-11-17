package usdt_test

import (
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/gma1k/podtrace/internal/usdt"
)

func TestAHugeStapsdtSectionIsReadOnlyUpToItsBound(t *testing.T) {
	desc := binary.LittleEndian.AppendUint64(nil, 0x401000)
	desc = binary.LittleEndian.AppendUint64(desc, 0)
	desc = binary.LittleEndian.AppendUint64(desc, 0)
	desc = append(desc, "provider\x00probe\x00-4@%edi\x00"...)
	notes := buildNoteEntry(3, "stapsdt", desc)
	notes = append(notes, make([]byte, 6<<20)...)
	path := buildELFWithNoteData(t, notes)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	probes, err := usdt.Scan(path)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != 1 || probes[0].Provider != "provider" || probes[0].PC != 0x401000 {
		t.Errorf("probes = %+v, want the one at the start of the section", probes)
	}
	if mib := (after.TotalAlloc - before.TotalAlloc) >> 20; mib >= 5 {
		t.Errorf("scanning allocated %d MiB of a 6 MiB section", mib)
	}
}
