package probes

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/gma1k/podtrace/internal/config"
)

type boundedSpecMap struct {
	fakeSpecMap
	capacity int
}

func (m *boundedSpecMap) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	if _, ok := m.entries[key.(uint64)]; !ok && len(m.entries) >= m.capacity {
		return fmt.Errorf("update: %w", unix.E2BIG)
	}
	return m.fakeSpecMap.Update(key, value, flags)
}

func TestAFullSpecMapRefusesTheNewSiteAndKeepsEveryLiveSpec(t *testing.T) {
	m := &boundedSpecMap{fakeSpecMap: fakeSpecMap{entries: map[uint64]bool{}}, capacity: 2}
	table := &usdtSpecTable{users: map[uint64]int{}}
	val := &usdtProbeValue{}

	for _, cookie := range []uint64{1, 2} {
		if err := table.hold(m, cookie, val); err != nil {
			t.Fatalf("hold %d: %v", cookie, err)
		}
	}
	err := table.hold(m, 3, val)
	if !usdtSpecMapFull(err) {
		t.Fatalf("hold on a full map = %v, want an error the attach loop recognises as a full map", err)
	}
	if !m.entries[1] || !m.entries[2] || m.entries[3] {
		t.Errorf("entries %v, want the two live specs kept and the third refused", m.entries)
	}
	if _, counted := table.users[3]; counted {
		t.Error("a refused spec was counted as held, so its release would delete a spec it never wrote")
	}
	if err := table.hold(m, 1, val); err != nil {
		t.Errorf("a second site of a live spec must not need a free slot: %v", err)
	}
	table.release(m, 2)
	if err := table.hold(m, 3, val); err != nil {
		t.Errorf("a slot freed by the last site of a spec must take a new spec: %v", err)
	}
}

func TestOnlyACapacityErrorStopsTheUSDTAttachLoop(t *testing.T) {
	for _, err := range []error{nil, errors.New("attach failed"), unix.EINVAL, unix.ENOENT} {
		if usdtSpecMapFull(err) {
			t.Errorf("%v must skip the one probe, not every probe after it", err)
		}
	}
}

type fullSpecMap struct {
	updates int
}

func (m *fullSpecMap) Update(_, _ any, _ ebpf.MapUpdateFlags) error {
	m.updates++
	return fmt.Errorf("update: %w", unix.E2BIG)
}

func (m *fullSpecMap) Delete(any) error { return nil }

func TestAFullSpecMapStopsAttachingTheRestOfTheBinarysProbes(t *testing.T) {
	const pid = 4310
	sections := rustLikeSections("f")
	notes := append(stapsdtNote(testTextVA, "app", "tick"), stapsdtNote(testTextVA+0x4, "app", "tock")...)
	sections = append(sections, testSection{name: ".note.stapsdt", typ: shtNote, data: notes})
	syntheticProc(t, pid, sections)
	addLoadSegment(t, filepath.Join(config.ProcBasePath, strconv.FormatUint(uint64(pid), 10), "exe"), 0x400000)
	origEnabled, origMap, origSpecs := config.USDTEnabled, usdtSpecMapOf, usdtSpecs
	m := &fullSpecMap{}
	config.USDTEnabled = true
	usdtSpecMapOf = func(*ebpf.Collection) usdtSpecMap { return m }
	usdtSpecs = &usdtSpecTable{users: map[uint64]int{}}
	t.Cleanup(func() {
		config.USDTEnabled, usdtSpecMapOf, usdtSpecs = origEnabled, origMap, origSpecs
	})
	f := installFakeAttacher(t, nil)

	links := AttachUSDTProbes(placeholderPrograms("uprobe_usdt"), pid)
	if len(links) != 0 || len(f.calls) != 0 {
		t.Errorf("links=%d attaches=%d on a full spec map, want none", len(links), len(f.calls))
	}
	if m.updates != 1 {
		t.Errorf("%d spec writes, want 1: a full map must stop the loop, not be retried for every probe", m.updates)
	}
}
