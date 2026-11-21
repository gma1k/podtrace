//go:build integration
// +build integration

package test

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/h3decode"
	"github.com/gma1k/podtrace/internal/ebpf/h3stream"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/redactor"
)

func h3HeadersChunk(conn, stream uint64, section []byte) h3stream.Chunk {
	data := []byte{0x01}
	n := len(section)
	switch {
	case n < 64:
		data = append(data, byte(n))
	case n < 16384:
		data = append(data, byte(0x40|n>>8), byte(n))
	default:
		data = append(data, byte(0x80|n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	data = append(data, section...)
	return h3stream.Chunk{
		TGID:      7,
		Conn:      conn,
		StreamID:  stream,
		StreamLen: uint32(len(data)),
		CopiedLen: uint32(len(data)),
		Data:      data,
	}
}

func h3PathSection(path string) []byte {
	section := []byte{0x00, 0x00, 0xd1, 0x51}
	n := len(path)
	if n < 127 {
		section = append(section, byte(n))
	} else {
		section = append(section, 0x7f)
		n -= 127
		for n >= 0x80 {
			section = append(section, byte(n&0x7f)|0x80)
			n >>= 7
		}
		section = append(section, byte(n))
	}
	return append(section, path...)
}

func TestH3FieldLineFloodDoesNotPinAgentMemory(t *testing.T) {
	stash := h3stream.NewSectionStash(5*time.Second, 2048)
	asm := h3stream.NewAssembler(func(k h3stream.ConnKey, sec h3stream.Section) {
		stash.Put(h3stream.SectionKey{TGID: k.TGID, Conn: k.Conn, Stream: sec.StreamID}, sec)
	})
	flood := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0xd1}, 4080)...)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for conn := uint64(1); conn <= 32; conn++ {
		for stream := uint64(0); stream < 64; stream++ {
			asm.Feed(h3HeadersChunk(conn, stream*4, flood))
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(stash)

	if grown := int64(after.HeapAlloc) - int64(before.HeapAlloc); grown > 64<<20 {
		t.Fatalf("flood of 2048 field-line bombs grew the heap by %d MiB", grown>>20)
	}
	if _, ok := stash.Take(h3stream.SectionKey{TGID: 7, Conn: 1, Stream: 0}); ok {
		t.Fatal("section over the field-line cap reached the stash")
	}
}

func TestH3StashedSectionEnrichesARedactedTransaction(t *testing.T) {
	stash := h3stream.NewSectionStash(5*time.Second, 2048)
	asm := h3stream.NewAssembler(func(k h3stream.ConnKey, sec h3stream.Section) {
		stash.Put(h3stream.SectionKey{TGID: k.TGID, Conn: k.Conn, Stream: sec.StreamID}, sec)
	})
	asm.Feed(h3HeadersChunk(9, 4, h3PathSection("/login?password=hunter2&"+strings.Repeat("a", 3000))))

	sec, ok := stash.Take(h3stream.SectionKey{TGID: 7, Conn: 9, Stream: 4})
	if !ok {
		t.Fatal("section not stashed")
	}
	txn := &h3decode.Txn{PID: 7, Status: 200, Flags: h3decode.FlagResponseOnly}
	if !h3stream.EnrichTxn(txn, sec) {
		t.Fatal("transaction not enriched")
	}
	evs := txn.Events()
	if len(evs) == 0 {
		t.Fatal("no events")
	}
	r := redactor.Default()
	for _, ev := range evs {
		r.Redact(ev)
		if strings.Contains(ev.Target, "hunter2") {
			t.Fatalf("secret in %s target: %q", ev.TypeString(), ev.Target)
		}
		if ev.Type == events.EventHTTPReq && !strings.HasPrefix(ev.Target, "GET /login?password=***") {
			t.Fatalf("request target = %.60q", ev.Target)
		}
		if len(ev.Target) > 2100 {
			t.Fatalf("target of %d bytes escaped the section bound", len(ev.Target))
		}
	}
}

func TestRedactorMasksCompoundCredentialsInCapturedBodies(t *testing.T) {
	ev := &events.Event{
		Type:    events.EventHTTPReq,
		Target:  "POST /api/users",
		Details: `{"user":"bob","newPassword":"hunter2","apiKeys":["k1"],"aws_secret_access_key":"hunter3"} <dbPassword>hunter4</dbPassword>`,
	}
	redactor.Default().Redact(ev)
	for _, secret := range []string{"hunter2", "hunter3", "hunter4"} {
		if strings.Contains(ev.Details, secret) {
			t.Fatalf("%s leaked: %q", secret, ev.Details)
		}
	}
	if !strings.Contains(ev.Details, `"user":"bob"`) {
		t.Fatalf("non-secret context lost: %q", ev.Details)
	}
}
