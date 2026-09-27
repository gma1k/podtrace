package oncpu

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

type fakePerf struct {
	openErr map[int]error
	bpfErr  map[int]error
	attrs   []unix.PerfEventAttr
	closed  []int
	bound   map[int]int
}

func useFakePerf(t *testing.T, cpus string, f *fakePerf) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "online")
	if err := os.WriteFile(path, []byte(cpus+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.bound = map[int]int{}
	origPath, origOpen, origSet, origClose := onlineCPUsPath, perfEventOpen, setBPF, closeFD
	onlineCPUsPath = path
	perfEventOpen = func(attr *unix.PerfEventAttr, pid, cpu, group int, flags int) (int, error) {
		f.attrs = append(f.attrs, *attr)
		if pid != -1 || group != -1 || flags&unix.PERF_FLAG_FD_CLOEXEC == 0 {
			t.Errorf("perf_event_open(pid=%d, group=%d, flags=%#x): want every task on the CPU, no group, CLOEXEC", pid, group, flags)
		}
		if err := f.openErr[cpu]; err != nil {
			return -1, err
		}
		return 100 + cpu, nil
	}
	setBPF = func(fd, prog int) error {
		if err := f.bpfErr[fd-100]; err != nil {
			return err
		}
		f.bound[fd] = prog
		return nil
	}
	closeFD = func(fd int) error {
		f.closed = append(f.closed, fd)
		if fd == 999 {
			return errors.New("close failed")
		}
		return nil
	}
	t.Cleanup(func() { onlineCPUsPath, perfEventOpen, setBPF, closeFD = origPath, origOpen, origSet, origClose })
}

func TestTheSamplerRunsAtAFixedRateOnEveryOnlineCPU(t *testing.T) {
	f := &fakePerf{}
	useFakePerf(t, "0-2,4", f)

	s, err := attach(7)
	if err != nil {
		t.Fatal(err)
	}
	if s.CPUs() != 4 {
		t.Errorf("sampling %d CPUs, want 4", s.CPUs())
	}
	if !reflect.DeepEqual(f.bound, map[int]int{100: 7, 101: 7, 102: 7, 104: 7}) {
		t.Errorf("program bound to %v", f.bound)
	}
	a := f.attrs[0]
	if a.Type != unix.PERF_TYPE_SOFTWARE || a.Config != unix.PERF_COUNT_SW_CPU_CLOCK ||
		a.Sample != SampleHz || a.Bits&unix.PerfBitFreq == 0 || a.Size == 0 {
		t.Errorf("attr = %+v, want a cpu-clock software event sampling at %d Hz", a, SampleHz)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if len(f.closed) != 4 || s.CPUs() != 0 {
		t.Errorf("closed %v; every CPU's event must be released", f.closed)
	}
}

func TestACPUThatRefusesTheEventIsSkipped(t *testing.T) {
	f := &fakePerf{
		openErr: map[int]error{1: unix.ENODEV},
		bpfErr:  map[int]error{2: unix.EINVAL},
	}
	useFakePerf(t, "0-2", f)

	s, err := attach(7)
	if err != nil {
		t.Fatal(err)
	}
	if s.CPUs() != 1 {
		t.Errorf("sampling %d CPUs, want only cpu 0", s.CPUs())
	}
	if len(f.closed) != 1 || f.closed[0] != 102 {
		t.Errorf("closed %v; the event whose attach failed must not leak", f.closed)
	}
}

func TestTheAttachFailsWhenNoCPUAcceptsTheEvent(t *testing.T) {
	f := &fakePerf{openErr: map[int]error{0: unix.EACCES, 1: unix.EACCES}}
	useFakePerf(t, "0-1", f)
	if _, err := attach(7); !errors.Is(err, unix.EACCES) {
		t.Errorf("attach = %v, want the first CPU's error", err)
	}

	g := &fakePerf{bpfErr: map[int]error{0: unix.EINVAL}}
	useFakePerf(t, "0", g)
	if _, err := attach(7); !errors.Is(err, unix.EINVAL) {
		t.Errorf("attach = %v, want the attach error", err)
	}
}

func TestTheAttachFailsWithoutAReadableCPUList(t *testing.T) {
	useFakePerf(t, "0", &fakePerf{})
	onlineCPUsPath = filepath.Join(t.TempDir(), "missing")
	if _, err := attach(7); err == nil {
		t.Error("no error for an unreadable CPU list")
	}
}

func TestAttachRefusesAMissingProgram(t *testing.T) {
	if _, err := Attach(nil); err == nil {
		t.Error("no error for an object without the sampler program")
	}
}

func TestCloseReportsAFailureAndIsSafeWhenNil(t *testing.T) {
	useFakePerf(t, "0", &fakePerf{})
	s := &Sampler{fds: []int{999, 5}}
	if err := s.Close(); err == nil {
		t.Error("a close failure was swallowed")
	}
	var none *Sampler
	if none.CPUs() != 0 || none.Close() != nil {
		t.Error("a nil sampler is not inert")
	}
}

func TestTheCPUListIsParsed(t *testing.T) {
	for list, want := range map[string][]int{
		"0":        {0},
		"0-3":      {0, 1, 2, 3},
		"0,2-3,,7": {0, 2, 3, 7},
		"1-1":      {1},
	} {
		got, err := parseCPUList(list)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("parseCPUList(%q) = %v, %v; want %v", list, got, err, want)
		}
	}
	for _, bad := range []string{"", "x", "1-x", "3-1", ","} {
		if _, err := parseCPUList(bad); err == nil {
			t.Errorf("parseCPUList(%q) accepted a malformed list", bad)
		}
	}
}
