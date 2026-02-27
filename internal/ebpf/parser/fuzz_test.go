package parser

import (
	"testing"
	"unsafe"
)

// FuzzParseEvent fuzzes the BPF event parser with arbitrary byte slices.
// It verifies that ParseEvent never panics, regardless of input size or content.
func FuzzParseEvent(f *testing.F) {
	// Seed corpus: valid V1/V2/V3-sized zero-value structs
	f.Add(make([]byte, int(unsafe.Sizeof(rawEvent{}))))
	f.Add(make([]byte, int(unsafe.Sizeof(rawEvent{}))+8))            // V2 size (adds CgroupID)
	f.Add(make([]byte, int(unsafe.Sizeof(rawEvent{}))+8+16))         // V3 size (adds CgroupID + Comm)
	f.Add([]byte{})                                                   // too short → must return nil
	f.Add(make([]byte, 1))                                            // too short
	f.Add(make([]byte, int(unsafe.Sizeof(rawEvent{}))-1))            // one byte short of V1

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic
		event := ParseEvent(data)
		if event != nil {
			// Return the event to the pool to avoid leaking
			PutEvent(event)
		}
	})
}
