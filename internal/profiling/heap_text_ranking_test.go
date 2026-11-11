package profiling

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func heapTextWithUniqueFrames(n int) string {
	var b strings.Builder
	b.WriteString("heap profile: 1: 1 [1: 1] @ heap/1048576\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "1: %d [1: %d] @ 0x1\n#\t0x1\tpkg.f%d+0x1\t/f.go:1\n\n", i+1, i+1, i)
	}
	return b.String()
}

func TestParsingAHeapProfileWithManyUniqueFramesIsNotQuadratic(t *testing.T) {
	text := heapTextWithUniqueFrames(200_000)
	start := time.Now()
	top := parseHeapText(text)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("parsing 200k unique frames took %v", elapsed)
	}
	if len(top) != maxTopFunctions || top[0].Function != "pkg.f199999" || top[0].Bytes != 200_000 {
		t.Errorf("top = %v, want the 20 largest with pkg.f199999 first", top[:min(len(top), 3)])
	}
}

func TestHeapFunctionsWithEqualBytesAreOrderedByName(t *testing.T) {
	text := "1: 64 [1: 64] @ 0x1\n#\t0x1\tpkg.zeta+0x1\t/f.go:1\n\n" +
		"1: 64 [1: 64] @ 0x2\n#\t0x2\tpkg.alpha+0x1\t/f.go:1\n\n" +
		"1: 64 [1: 64] @ 0x3\n#\t0x3\tpkg.mid+0x1\t/f.go:1\n\n"
	for i := 0; i < 20; i++ {
		top := parseHeapText(text)
		if len(top) != 3 || top[0].Function != "pkg.alpha" || top[1].Function != "pkg.mid" || top[2].Function != "pkg.zeta" {
			t.Fatalf("top = %v, want alpha, mid, zeta", top)
		}
	}
}
