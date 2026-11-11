package stacktrace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func countingAddr2line(t *testing.T, answer string) func() int {
	t.Helper()
	dir := t.TempDir()
	fakeAddr2line(t, "echo run >> "+filepath.Join(dir, "runs")+"\necho '"+answer+"'")
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return func() int {
		data, err := root.ReadFile("runs")
		if err != nil {
			return 0
		}
		return strings.Count(string(data), "run")
	}
}

func TestAStrippedExecutableStopsReachingAddr2lineAfterAFewMisses(t *testing.T) {
	runs := countingAddr2line(t, "??:0")
	pid := processOfTheTestBinary(t)
	r := &stackResolver{cache: map[string]string{}}
	for i := uint64(0); i < 50; i++ {
		got := r.resolve(context.Background(), pid, 0x1000+i)
		if !strings.Contains(got, "@0x") {
			t.Fatalf("resolve = %q, want the raw address", got)
		}
	}
	if n := runs(); n != maxAddr2lineMissesPerFile {
		t.Errorf("addr2line ran %d times on a binary it never resolved, want %d", n, maxAddr2lineMissesPerFile)
	}
}

func TestAddr2lineRunsAreCappedPerReportEvenWhenItAnswers(t *testing.T) {
	runs := countingAddr2line(t, "/src/app/main.go:42")
	pid := processOfTheTestBinary(t)
	r := &stackResolver{cache: map[string]string{}}
	var resolved, raw int
	for i := uint64(0); i < 2*maxAddr2lineRunsPerReport; i++ {
		got := r.resolve(context.Background(), pid, 0x1000+i)
		switch {
		case strings.HasSuffix(got, ":/src/app/main.go:42"):
			resolved++
		case strings.Contains(got, "@0x"):
			raw++
		default:
			t.Fatalf("resolve = %q", got)
		}
	}
	if n := runs(); n != maxAddr2lineRunsPerReport {
		t.Errorf("addr2line ran %d times, want the per-report cap %d", n, maxAddr2lineRunsPerReport)
	}
	if resolved != maxAddr2lineRunsPerReport || raw != maxAddr2lineRunsPerReport {
		t.Errorf("resolved %d and fell back on %d, want %d each", resolved, raw, maxAddr2lineRunsPerReport)
	}
}

func TestAnExecutableAddr2lineHasAnsweredKeepsUsingItPastTheMissLimit(t *testing.T) {
	r := &stackResolver{}
	id := fileID{dev: 1, ino: 2}
	r.recordAddr2line(id, true, true)
	for i := 0; i < 2*maxAddr2lineMissesPerFile; i++ {
		r.recordAddr2line(id, true, false)
	}
	if !r.addr2lineAllowed(id, true) {
		t.Error("a binary addr2line resolved once was cut off by later misses")
	}
	other := fileID{dev: 1, ino: 3}
	for i := 0; i < maxAddr2lineMissesPerFile; i++ {
		r.recordAddr2line(other, true, false)
	}
	if r.addr2lineAllowed(other, true) {
		t.Error("a binary that only missed was still sent to addr2line")
	}
	if !r.addr2lineAllowed(fileID{}, false) {
		t.Error("a file that could not be identified was refused before the report cap")
	}
	r.recordAddr2line(fileID{}, false, false)
	if len(r.addr2lineFiles) != 2 {
		t.Errorf("an unidentified file was recorded: %v", r.addr2lineFiles)
	}
}
