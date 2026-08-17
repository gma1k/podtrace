package tracer

import (
	"testing"

	"github.com/cilium/ebpf"
)

func emptyColl() *ebpf.Collection {
	return &ebpf.Collection{Maps: map[string]*ebpf.Map{}}
}

func TestMapHelpers_NilAndMissingMapGuards(t *testing.T) {
	if err := (&Tracer{}).setCgroupFilterEnabled(true); err != nil {
		t.Errorf("setCgroupFilterEnabled nil collection: %v", err)
	}
	if err := (&Tracer{collection: emptyColl()}).setCgroupFilterEnabled(true); err != nil {
		t.Errorf("setCgroupFilterEnabled missing map: %v", err)
	}

	setDNSPayloadFlag(nil, true)
	setDNSPayloadFlag(emptyColl(), true)

	populatePidNamespace(&ebpf.Collection{})

	populateCaptureHeaderNames(nil, nil)
	populateCaptureHeaderNames(&ebpf.Collection{}, []string{"x-request-id"})

	(&Tracer{}).recordDNSDrops()
	(&Tracer{collection: emptyColl()}).recordDNSDrops()

	(&Tracer{}).pollBPFMapUtilization()
	(&Tracer{collection: emptyColl()}).pollBPFMapUtilization()

	if err := (&Tracer{}).syncTargetCgroupMap(); err != nil {
		t.Errorf("syncTargetCgroupMap nil collection: %v", err)
	}
	if err := (&Tracer{collection: emptyColl()}).syncTargetCgroupMap(); err != nil {
		t.Errorf("syncTargetCgroupMap missing map: %v", err)
	}
}

func TestGetCgroupIDFromPath(t *testing.T) {
	if _, err := getCgroupIDFromPath("/nonexistent/path/does-not-exist-xyz"); err == nil {
		t.Error("expected error for nonexistent path")
	}
	id, err := getCgroupIDFromPath(t.TempDir())
	if err != nil {
		t.Fatalf("stat existing dir: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero inode")
	}
}
