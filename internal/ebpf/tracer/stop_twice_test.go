package tracer

import (
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/cache"
)

func TestStoppingTheTracerTwiceIsSafe(t *testing.T) {
	tr := &Tracer{processNameCache: cache.NewLRUCache(8, time.Minute)}
	if err := tr.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := tr.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}
