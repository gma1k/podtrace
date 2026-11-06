package procfs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

const fullStat = "4242 (my (odd) proc) S 1 4242 4242 0 -1 4194304 10 0 0 0 150 25 0 0 20 0 1 0 98765 1000 100"

func TestParseProcessStatReadsTicksPastACommWithParentheses(t *testing.T) {
	st, err := ParseProcessStat([]byte(fullStat))
	if err != nil {
		t.Fatal(err)
	}
	if st.Comm != "my (odd) proc" || st.UserTicks != 150 || st.SystemTicks != 25 || st.StartTicks != 98765 {
		t.Fatalf("parsed %+v", st)
	}
}

func TestParseProcessStatRejectsMalformedContents(t *testing.T) {
	for name, data := range map[string]string{
		"no comm":         "4242 S 1",
		"truncated":       "4242 (worker) S 1 2 3",
		"bad user ticks":  "4242 (w) S 1 1 1 0 -1 0 0 0 0 0 x 0 0 0 20 0 1 0 5 0 0",
		"bad sys ticks":   "4242 (w) S 1 1 1 0 -1 0 0 0 0 0 0 x 0 0 20 0 1 0 5 0 0",
		"bad start ticks": "4242 (w) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 x 0 0",
	} {
		if _, err := ParseProcessStat([]byte(data)); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

func TestStatCommSurvivesTruncatedFields(t *testing.T) {
	if comm, ok := StatComm([]byte("4242 (worker) S")); !ok || comm != "worker" {
		t.Fatalf("StatComm = %q, %v", comm, ok)
	}
	if _, ok := StatComm([]byte("4242 worker")); ok {
		t.Fatal("a stat without a comm yielded one")
	}
}

func TestStartTicksReadsTheProcessStatFile(t *testing.T) {
	base := t.TempDir()
	prev := config.ProcBasePath
	config.SetProcBasePath(base)
	ResetForTesting()
	t.Cleanup(func() {
		config.SetProcBasePath(prev)
		ResetForTesting()
	})
	if err := os.MkdirAll(filepath.Join(base, "4242"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "4242", "stat"), []byte(fullStat), 0o644); err != nil {
		t.Fatal(err)
	}
	if start, ok := StartTicks(4242); !ok || start != 98765 {
		t.Fatalf("StartTicks = %d, %v", start, ok)
	}
	if _, ok := StartTicks(4343); ok {
		t.Fatal("a missing process reported a start time")
	}
}
