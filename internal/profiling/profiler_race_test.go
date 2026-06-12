package profiling

import (
	"context"
	"sync"
	"testing"
)

// TestPodProfiler_DiscoverFetchRace: Discover writes foundPort while HTTP
// handler goroutines read it concurrently — a plain int field raced. Run
// under -race.
func TestPodProfiler_DiscoverFetchRace(t *testing.T) {
	p := NewPodProfiler("127.0.0.1", []int{1}) // closed port: Discover fails fast
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			p.Discover(context.Background())
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_ = p.FetchHeap(context.Background())
			_ = p.FetchGoroutine(context.Background())
		}
	}()
	wg.Wait()
}
