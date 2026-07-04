package tracer

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/ebpf/h3decode"
	"github.com/podtrace/podtrace/internal/ebpf/h3stream"
)

func TestH3EnrichOrParkStreamZero(t *testing.T) {
	stash := h3stream.NewSectionStash(time.Minute, 16)
	stash.Put(h3stream.SectionKey{TGID: 7, Conn: 0xfeed, Stream: 0},
		h3stream.Section{Status: 200})
	tr := &Tracer{h3SectionStash: stash}

	txn := &h3decode.Txn{PID: 7, AdapterConn: 0xfeed, AdapterStream: 0, IsClient: true}
	if parked := tr.h3EnrichOrPark(txn); parked {
		t.Fatal("txn with available section was parked")
	}
	if txn.Status != 200 {
		t.Fatalf("status = %d, want 200 (stream-0 join failed)", txn.Status)
	}
}

func TestH3EnrichOrParkRequestOnlyNotParked(t *testing.T) {
	tr := &Tracer{h3SectionStash: h3stream.NewSectionStash(time.Minute, 16)}
	txn := &h3decode.Txn{
		PID: 7, AdapterConn: 0xbeef, IsClient: true,
		Flags: h3decode.FlagRequestOnly,
	}
	if parked := tr.h3EnrichOrPark(txn); parked {
		t.Fatal("request-only txn was parked")
	}
}

func TestH3EnrichOrParkParksPairedClientTxn(t *testing.T) {
	stash := h3stream.NewSectionStash(time.Minute, 16)
	tr := &Tracer{h3SectionStash: stash}
	txn := &h3decode.Txn{PID: 7, AdapterConn: 0xfeed, AdapterStream: 4, IsClient: true}

	if parked := tr.h3EnrichOrPark(txn); !parked {
		t.Fatal("client txn without section was not parked")
	}
	if len(tr.h3Parked) != 1 {
		t.Fatalf("parked list has %d entries, want 1", len(tr.h3Parked))
	}
}