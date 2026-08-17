package tracer

import "testing"

func TestRecoverReaderPanic_SwallowsPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("recoverReaderPanic let a panic escape: %v", r)
		}
	}()
	func() {
		defer recoverReaderPanic("http/2 decode")
		panic("malformed record")
	}()
}

func TestRecoverReaderPanic_NoPanicIsNoop(t *testing.T) {
	func() {
		defer recoverReaderPanic("dns payload")
	}()
}
