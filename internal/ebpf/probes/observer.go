package probes

import "sync"

// AttachObserver receives a notification for every failed BPF program
// attach.
type AttachObserver interface {
	OnAttachFailure(program, symbol string, mandatory bool, err error)
}

// observer is a package-level hook set by the agent before tracer
// construction.
var (
	observerMu sync.RWMutex
	observer   AttachObserver
)

// SetAttachObserver registers the observer that will be
// notified for each attach failure.
func SetAttachObserver(o AttachObserver) {
	observerMu.Lock()
	observer = o
	observerMu.Unlock()
}

// reportAttachFailure forwards a failure to the registered observer,
// if any.
func reportAttachFailure(program, symbol string, mandatory bool, err error) {
	observerMu.RLock()
	o := observer
	observerMu.RUnlock()
	if o != nil {
		o.OnAttachFailure(program, symbol, mandatory, err)
	}
}