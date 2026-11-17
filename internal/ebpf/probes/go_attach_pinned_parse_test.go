package probes

import (
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func TestGoProbesResolveEverySymbolFromTheExecutableTheyHoldOpen(t *testing.T) {
	const pid = 52301
	fakeProcTree(t, pid)
	f := installFakeAttacher(t, nil)
	orig := config.ContinuousProfilingEnabled
	config.ContinuousProfilingEnabled = true
	t.Cleanup(func() { config.ContinuousProfilingEnabled = orig })

	coll := placeholderPrograms(
		"uprobe_go_tls_write", "uprobe_go_tls_read", "uprobe_go_tls_read_ret",
		"uprobe_grpc_go_write_header",
		"uprobe_h3_write_header", "uprobe_h3_qpack_write_field",
		"uprobe_go_h2_serve_conn",
	)
	counts := map[string]int{
		"tls":     len(AttachGoTLSProbes(coll, pid)),
		"grpc":    len(AttachGoGRPCProbes(coll, pid)),
		"http3":   len(AttachGoHTTP3Probes(coll, pid)),
		"request": len(AttachGoRequestProbes(coll, pid)),
	}
	for name, n := range counts {
		if n == 0 {
			t.Errorf("%s attached nothing", name)
		}
	}
	if len(f.calls) == 0 {
		t.Fatal("no uprobe reached the attacher")
	}
}

func TestThePoolWaitProbeResolvesFromTheExecutableItHoldsOpen(t *testing.T) {
	const pid = 52302
	fakeProcTree(t, pid)
	var parsed []string
	orig := goFuncReturns
	t.Cleanup(func() { goFuncReturns = orig })
	goFuncReturns = func(path, _ string) (uint64, []uint64, bool) {
		parsed = append(parsed, path)
		return 100, []uint64{110, 120}, true
	}
	f := installFakeAttacher(t, nil)
	exe := config.ProcBasePath + "/52302/exe"
	links := attachGoAcquireProbes(placeholderPrograms("uprobe_go_db_conn", "uprobe_go_db_conn_ret"), exe, pid)
	if len(links) != 3 || len(f.calls) != 3 || f.calls[0].addr != 100 {
		t.Fatalf("links=%d calls=%+v, want the entry at 100 and both returns", len(links), f.calls)
	}
	if len(parsed) != 1 || parsed[0] == exe {
		t.Errorf("offsets were parsed from %v, want the descriptor the executable holds, not a second open of %s", parsed, exe)
	}
}

func TestThePoolWaitProbeNeedsTheSymbolInTheExecutable(t *testing.T) {
	const pid = 52303
	syntheticProc(t, pid, rustLikeSections("not_go"))
	f := installFakeAttacher(t, nil)
	exe := config.ProcBasePath + "/52303/exe"
	if links := attachGoAcquireProbes(placeholderPrograms("uprobe_go_db_conn", "uprobe_go_db_conn_ret"), exe, pid); len(links) != 0 || len(f.calls) != 0 {
		t.Errorf("%d links and %d attaches for a binary without database/sql", len(links), len(f.calls))
	}
}

func TestUSDTProbesNeedTheProcessExecutable(t *testing.T) {
	usdtTarget(t, 52304, false)
	f := installFakeAttacher(t, nil)
	if links := AttachUSDTProbes(placeholderPrograms("uprobe_usdt"), 52399); len(links) != 0 || len(f.calls) != 0 {
		t.Errorf("%d links for a process with no executable", len(links))
	}
}
