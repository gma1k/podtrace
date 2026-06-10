package filter

import (
	"sync"
	"testing"
)

// TestCgroupFilter_ConcurrentSetAndCheck is a regression test for the data
// race between SetCgroupPaths (called on every agent reconcile) and
// IsPIDInCgroup (the event hot path): only pidCache used to be locked while
// the path map was swapped and iterated concurrently. Run under -race.
func TestCgroupFilter_ConcurrentSetAndCheck(t *testing.T) {
	f := NewCgroupFilter()
	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		paths := [][]string{
			{"/sys/fs/cgroup/kubepods/pod-a"},
			{"/sys/fs/cgroup/kubepods/pod-a", "/sys/fs/cgroup/kubepods/pod-b"},
			nil,
		}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			f.SetCgroupPaths(paths[i%len(paths)])
		}
	}()

	for i := 0; i < 5000; i++ {
		f.IsPIDInCgroup(uint32(i%200 + 1))
	}
	close(stop)
	wg.Wait()
}
