package probes

import (
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/config"
)

func withContinuousProfiling(t *testing.T, on bool) {
	t.Helper()
	orig := config.ContinuousProfilingEnabled
	config.ContinuousProfilingEnabled = on
	t.Cleanup(func() { config.ContinuousProfilingEnabled = orig })
}

func TestGoRequestProbesStayOffWithoutTheProfiler(t *testing.T) {
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{}}
	withContinuousProfiling(t, false)
	if ls := AttachGoRequestProbes(coll, uint32(os.Getpid())); ls != nil {
		t.Errorf("attached %d links with continuous profiling off", len(ls))
	}
	withContinuousProfiling(t, true)
	if AttachGoRequestProbes(coll, 0) != nil || AttachGoRequestProbes(nil, uint32(os.Getpid())) != nil {
		t.Error("attached without a process or a collection")
	}
}

func TestGoRequestProbesSkipAProcessThatIsGone(t *testing.T) {
	withContinuousProfiling(t, true)
	orig := config.ProcBasePath
	config.ProcBasePath = t.TempDir()
	t.Cleanup(func() { config.ProcBasePath = orig })
	if ls := AttachGoRequestProbes(&ebpf.Collection{}, 4242); ls != nil {
		t.Errorf("attached %d links to a missing executable", len(ls))
	}
}

func TestGoRequestProbesNeedTheirPrograms(t *testing.T) {
	withContinuousProfiling(t, true)
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{}}
	if ls := AttachGoRequestProbes(coll, uint32(os.Getpid())); len(ls) != 0 {
		t.Errorf("attached %d links from an object without the request programs", len(ls))
	}
}

func TestEveryGoRequestSymbolNamesAHandlerAndItsPrograms(t *testing.T) {
	for _, h := range goRequestHandlers {
		if !strings.Contains(h.symbol, ".") || h.entryProg == "" || h.retProg != h.entryProg+"_ret" {
			t.Errorf("handler %+v: want a Go symbol and an entry program with a matching _ret program", h)
		}
	}
	for _, c := range goConnectionServers {
		if !strings.HasSuffix(strings.ToLower(c.symbol), ".serveconn") || c.prog == "" {
			t.Errorf("connection server %+v", c)
		}
	}
	seen := map[string]bool{}
	for _, h := range goRequestHandlers {
		if seen[h.symbol] {
			t.Errorf("%s is listed twice", h.symbol)
		}
		seen[h.symbol] = true
	}
}

func TestGoRequestProbesAreWantedByTheProfilerOrByRequestStamping(t *testing.T) {
	origStamping := config.RequestStamping
	t.Cleanup(func() { config.RequestStamping = origStamping })
	for _, c := range []struct{ profiling, stamping, want bool }{
		{false, false, false},
		{true, false, true},
		{false, true, true},
		{true, true, true},
	} {
		withContinuousProfiling(t, c.profiling)
		config.RequestStamping = c.stamping
		if got := goRequestProbesWanted(); got != c.want {
			t.Errorf("profiling=%v stamping=%v: wanted=%v", c.profiling, c.stamping, got)
		}
	}
}
