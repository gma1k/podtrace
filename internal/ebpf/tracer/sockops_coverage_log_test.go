package tracer

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/config"
)

type coverageLog struct{ lines []sockOpsCoverage }

func captureCoverageLog(t *testing.T) *coverageLog {
	t.Helper()
	c := &coverageLog{}
	orig := logSockOpsCoverage
	logSockOpsCoverage = func(now sockOpsCoverage, _, _ int) { c.lines = append(c.lines, now) }
	t.Cleanup(func() { logSockOpsCoverage = orig })

	origEnabled := config.SockOpsRTTEnabled
	config.SockOpsRTTEnabled = true
	t.Cleanup(func() { config.SockOpsRTTEnabled = origEnabled })
	return c
}

func TestSockOpsCoverageIsLoggedOnceNotOncePerPod(t *testing.T) {
	logged := captureCoverageLog(t)
	rec := &attachRecorder{}
	swapAttach(t, &attachSockOpsProbes, rec.attach)
	tr := reconcileTracer()

	tr.syncSockOpsProbes([]string{"/cg/a"})
	tr.syncSockOpsProbes([]string{"/cg/a", "/cg/b"})
	tr.syncSockOpsProbes([]string{"/cg/a", "/cg/b", "/cg/c"})
	tr.syncSockOpsProbes([]string{"/cg/b"})

	if len(logged.lines) != 1 || logged.lines[0] != sockOpsCoverageAttached {
		t.Errorf("logged %v, want a single attached line; one line per pod cgroup floods the "+
			"agent log on a busy node", logged.lines)
	}
}

func TestAKernelWithoutSockOpsWarnsOnce(t *testing.T) {
	logged := captureCoverageLog(t)
	swapAttach(t, &attachSockOpsProbes, func(*ebpf.Collection, []string) []link.Link { return nil })
	tr := reconcileTracer()

	for _, pods := range [][]string{{"/cg/a"}, {"/cg/a", "/cg/b"}, {"/cg/c"}} {
		tr.syncSockOpsProbes(pods)
	}

	if len(logged.lines) != 1 || logged.lines[0] != sockOpsCoverageNone {
		t.Errorf("logged %v, want one attached-to-nothing warning, not one per pod", logged.lines)
	}
}

func TestLosingAndRegainingCoverageIsEachLogged(t *testing.T) {
	logged := captureCoverageLog(t)
	works := true
	rec := &attachRecorder{}
	swapAttach(t, &attachSockOpsProbes, func(c *ebpf.Collection, p []string) []link.Link {
		if !works {
			return nil
		}
		return rec.attach(c, p)
	})
	tr := reconcileTracer()

	tr.syncSockOpsProbes([]string{"/cg/a"})
	works = false
	tr.syncSockOpsProbes([]string{"/cg/b"})
	works = true
	tr.syncSockOpsProbes([]string{"/cg/c"})

	want := []sockOpsCoverage{sockOpsCoverageAttached, sockOpsCoverageNone, sockOpsCoverageAttached}
	if len(logged.lines) != len(want) {
		t.Fatalf("logged %v, want %v", logged.lines, want)
	}
	for i := range want {
		if logged.lines[i] != want[i] {
			t.Errorf("line %d = %v, want %v", i, logged.lines[i], want[i])
		}
	}
}

func TestNothingIsLoggedWhenNothingIsWanted(t *testing.T) {
	logged := captureCoverageLog(t)
	swapAttach(t, &attachSockOpsProbes, func(*ebpf.Collection, []string) []link.Link { return nil })
	orig := kubepodsRoot
	kubepodsRoot = func() string { return "" }
	t.Cleanup(func() { kubepodsRoot = orig })

	reconcileTracer().syncSockOpsProbes(nil)

	if len(logged.lines) != 0 {
		t.Errorf("logged %v with no cgroup to attach to", logged.lines)
	}
}

func TestTheRealCoverageLineWritesBothOutcomes(t *testing.T) {
	orig := kubepodsRoot
	var asked bool
	kubepodsRoot = func() string { asked = true; return "/sys/fs/cgroup/kubepods.slice" }
	t.Cleanup(func() { kubepodsRoot = orig })

	logSockOpsCoverage(sockOpsCoverageAttached, 3, 3)
	if asked {
		t.Error("the attached line looked up the kubepods root it does not report")
	}
	logSockOpsCoverage(sockOpsCoverageNone, 0, 3)
	if !asked {
		t.Error("the attached-to-nothing warning did not report the kubepods root, which is what " +
			"tells an operator where the hook tried to attach")
	}
}
