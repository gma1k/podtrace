package profiling

import "testing"

func TestGoroutineWaitReasonsSinceGo120CountAsBlocked(t *testing.T) {
	text := `goroutine 1 [running]:
main.main()

goroutine 2 [sync.Mutex.Lock]:
sync.(*Mutex).Lock()

goroutine 3 [sync.RWMutex.RLock, 3 minutes]:
sync.(*RWMutex).RLock()

goroutine 4 [sync.Cond.Wait]:
sync.(*Cond).Wait()

goroutine 5 [sync.WaitGroup.Wait]:
sync.(*WaitGroup).Wait()

goroutine 6 [chan receive (nil chan)]:
main.leak()

goroutine 7 [select (no cases)]:
main.forever()

goroutine 8 [chan receive, locked to thread]:
main.worker()

goroutine 9 [runnable]:
main.spin()

goroutine 10 [GC assist wait]:
runtime.gcAssistAlloc()
`
	total, blocked := parseGoroutineText(text)
	if total != 10 || blocked != 8 {
		t.Fatalf("total=%d blocked=%d, want 10 total and 8 blocked", total, blocked)
	}
}

func TestOnlyWaitingStatesAreBlocked(t *testing.T) {
	for state, want := range map[string]bool{
		"sync.Mutex.Lock": true,
		"semacquire":      true,
		"IO wait":         true,
		"running":         false,
		"runnable":        false,
		"syncing":         false,
		"sync":            false,
	} {
		if got := isBlockedWaitReason(state); got != want {
			t.Errorf("isBlockedWaitReason(%q) = %v, want %v", state, got, want)
		}
	}
}
