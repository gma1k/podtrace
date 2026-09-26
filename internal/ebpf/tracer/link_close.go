package tracer

import (
	"sync"

	"github.com/cilium/ebpf/link"
)

const maxConcurrentLinkCloses = 64

// closeLinksConcurrently closes every link, several at a time.
func closeLinksConcurrently(ls []link.Link, workers int) {
	if len(ls) == 0 {
		return
	}
	if workers < 1 {
		workers = 1
	}
	if workers > len(ls) {
		workers = len(ls)
	}
	next := make(chan link.Link)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for l := range next {
				if l != nil {
					_ = l.Close()
				}
			}
		}()
	}
	for _, l := range ls {
		next <- l
	}
	close(next)
	wg.Wait()
}
