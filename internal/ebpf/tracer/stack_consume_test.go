package tracer

import (
	"os"
	"regexp"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/podtrace/podtrace/internal/events"
)

func TestStackTracesMapDeclaredLRU(t *testing.T) {
	src, err := os.ReadFile("../../../bpf/maps.h")
	if err != nil {
		t.Fatalf("read bpf/maps.h: %v", err)
	}
	decl := regexp.MustCompile(`(?s)struct \{[^}]*\} stack_traces SEC`).Find(src)
	if decl == nil {
		t.Fatal("stack_traces map declaration not found in bpf/maps.h")
	}
	if !regexp.MustCompile(`BPF_MAP_TYPE_LRU_HASH`).Match(decl) {
		t.Errorf("stack_traces must be BPF_MAP_TYPE_LRU_HASH, got declaration:\n%s", decl)
	}
}

func TestTCPPeerStashDeclaredLRU(t *testing.T) {
	src, err := os.ReadFile("../../../bpf/maps.h")
	if err != nil {
		t.Fatalf("read bpf/maps.h: %v", err)
	}
	decl := regexp.MustCompile(`(?s)struct \{[^}]*\} tcp_peer_stash SEC`).Find(src)
	if decl == nil {
		t.Fatal("tcp_peer_stash map declaration not found in bpf/maps.h")
	}
	if !regexp.MustCompile(`BPF_MAP_TYPE_LRU_HASH`).Match(decl) {
		t.Errorf("tcp_peer_stash must be BPF_MAP_TYPE_LRU_HASH, got declaration:\n%s", decl)
	}
}

func TestResolveAndConsumeStack_DeletesEntry(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LRUHash,
		KeySize:    8,
		ValueSize:  uint32(unsafe.Sizeof(stackTraceValue{})),
		MaxEntries: 8,
	})
	if err != nil {
		t.Skipf("cannot create BPF map (requires CAP_BPF): %v", err)
	}
	defer func() { _ = m.Close() }()

	key := uint64(0xdeadbeef)
	value := stackTraceValue{Nr: 2}
	value.IPs[0] = 0x1000
	value.IPs[1] = 0x2000
	if err := m.Put(&key, &value); err != nil {
		t.Fatalf("put: %v", err)
	}

	event := &events.Event{StackKey: key}
	resolveAndConsumeStack(m, event)

	if len(event.Stack) != 2 || event.Stack[0] != 0x1000 || event.Stack[1] != 0x2000 {
		t.Errorf("stack not resolved onto event: %#v", event.Stack)
	}
	var out stackTraceValue
	if err := m.Lookup(&key, &out); err == nil {
		t.Error("consumed stack entry still present in map; it must be deleted after the read")
	}
}

func TestResolveAndConsumeStack_NilMapAndZeroKey(t *testing.T) {
	resolveAndConsumeStack(nil, &events.Event{StackKey: 1})

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LRUHash,
		KeySize:    8,
		ValueSize:  uint32(unsafe.Sizeof(stackTraceValue{})),
		MaxEntries: 8,
	})
	if err != nil {
		t.Skipf("cannot create BPF map (requires CAP_BPF): %v", err)
	}
	defer func() { _ = m.Close() }()

	event := &events.Event{StackKey: 0}
	resolveAndConsumeStack(m, event)
	if event.Stack != nil {
		t.Errorf("zero StackKey must not resolve a stack, got %#v", event.Stack)
	}
}
