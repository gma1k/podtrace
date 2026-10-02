package tracer

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestStampingNeedsALoadedObjectWithItsSwitch(t *testing.T) {
	var none *Tracer
	if err := none.StampRequests(); err == nil {
		t.Error("a nil tracer switched stamping on")
	}
	if err := (&Tracer{}).StampRequests(); err == nil {
		t.Error("a tracer with no object switched stamping on")
	}
	bare := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	if err := bare.StampRequests(); err == nil || bare.onCPUFlags != 0 {
		t.Errorf("an object without the switch map = %v, flags %d", err, bare.onCPUFlags)
	}
}
