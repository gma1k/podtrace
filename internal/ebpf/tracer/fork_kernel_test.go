//go:build bpf_loadtest && linux

package tracer

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/events"
)

func TestKernelAForkCarriesTheChildsPidAndName(t *testing.T) {
	log := traceGroup(t, probes.GroupCPU, func(ev *events.Event) bool {
		return ev.Type == events.EventFork
	})
	var pids []int
	for i := 0; i < 5; i++ {
		cmd := exec.Command("/bin/true")
		if err := cmd.Run(); err != nil {
			t.Fatalf("run a child: %v", err)
		}
		pids = append(pids, cmd.Process.Pid)
	}
	time.Sleep(2 * time.Second)

	byPID := map[uint32]*events.Event{}
	for _, ev := range log.events() {
		byPID[ev.PID] = ev
	}
	seen := 0
	for _, pid := range pids {
		ev, ok := byPID[uint32(pid)]
		if !ok {
			continue
		}
		seen++
		if ev.Target != "tracer.test" {
			t.Errorf("fork of pid %d names %q, want the forking program's name", pid, ev.Target)
		}
	}
	if seen == 0 {
		t.Errorf("none of the %d forked children was reported with its pid %v", len(pids), pids)
	}
}

func threadCount(t *testing.T) int {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if rest, ok := strings.CutPrefix(line, "Threads:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(rest))
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	}
	t.Fatal("no Threads line in /proc/self/status")
	return 0
}

func TestKernelANewThreadIsNotReportedAsAFork(t *testing.T) {
	log := traceGroup(t, probes.GroupCPU, func(ev *events.Event) bool {
		return ev.Type == events.EventFork
	})
	before := threadCount(t)
	var wg sync.WaitGroup
	release := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			ts := unix.NsecToTimespec(int64(200 * time.Millisecond))
			_ = unix.Nanosleep(&ts, nil)
			<-release
		}()
	}
	time.Sleep(300 * time.Millisecond)
	grown := threadCount(t) - before
	close(release)
	wg.Wait()
	child := exec.Command("/bin/true")
	if err := child.Run(); err != nil {
		t.Fatalf("run a child: %v", err)
	}
	time.Sleep(2 * time.Second)
	if grown <= 0 {
		t.Skip("the runtime started no new thread")
	}

	self := uint32(os.Getpid())
	var childSeen bool
	for _, ev := range log.events() {
		if ev.PID == self {
			t.Errorf("a fork event carries this process's own pid %d; it was a thread of this process, not a new process", self)
		}
		if ev.PID == uint32(child.Process.Pid) {
			childSeen = true
		}
	}
	if !childSeen {
		t.Error("the forked child was not reported, so this test proves nothing about threads")
	}
}
