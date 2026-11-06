package probes

import (
	"debug/dwarf"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/logger"
)

// grpcTransportPackage is the package that owns the hooked grpc-go receivers.
const grpcTransportPackage = "google.golang.org/grpc/internal/transport."

// grpcGoFieldOffsets mirrors struct grpc_go_field_offsets in bpf/maps.h: the
// offset of the per-connection *framer in each receiver the gRPC uprobes see.
// The writer goroutine (loopyWriter) and the reader goroutine
// (http2Server / http2Client) share that framer, so it pairs a request with
// its response on the same connection whichever OS thread each runs on.
type grpcGoFieldOffsets struct {
	LoopyFramer  uint32
	ServerFramer uint32
	ClientFramer uint32
	_            uint32
}

// grpcGoOffsetsFromDWARF reads the three framer offsets for the receiver
// types declared in pkg. All three must resolve to a pointer member.
func grpcGoOffsetsFromDWARF(d *dwarf.Data, idx map[string]dwarf.Offset, pkg string) (grpcGoFieldOffsets, bool) {
	framer := func(typeName string) (uint32, bool) {
		st := structByName(d, idx, pkg+typeName)
		if st == nil {
			return 0, false
		}
		f := findMember(st, "framer")
		if f == nil || !f.HasType {
			return 0, false
		}
		if ent, _, ok := stripType(d, f.Type); !ok || ent.Tag != dwarf.TagPointerType {
			return 0, false
		}
		return memberOffset32(f.ByteOffset)
	}
	var off grpcGoFieldOffsets
	var ok bool
	if off.LoopyFramer, ok = framer("loopyWriter"); !ok {
		return grpcGoFieldOffsets{}, false
	}
	if off.ServerFramer, ok = framer("http2Server"); !ok {
		return grpcGoFieldOffsets{}, false
	}
	if off.ClientFramer, ok = framer("http2Client"); !ok {
		return grpcGoFieldOffsets{}, false
	}
	return off, true
}

// resolveGRPCGoFieldOffsets reads the framer offsets from the target binary's
// DWARF, or from a separate build-id debug-info file. Without DWARF the BPF
// side falls back to the thread's last TCP 4-tuple, which pairs correctly
// only while a thread serves a single connection.
func resolveGRPCGoFieldOffsets(exePath string, pid uint32) (result grpcGoFieldOffsets, ok bool) {
	defer recoverParse("resolveGRPCGoFieldOffsets")
	d, closeFn, found := openDWARF(exePath, pid)
	if !found {
		return grpcGoFieldOffsets{}, false
	}
	defer closeFn()
	return grpcGoOffsetsFromDWARF(d, indexDWARFStructs(d), grpcTransportPackage)
}

// publishGRPCGoOffsets hands the framer offsets to BPF, keyed by tgid. A
// process without them has any entry left by an earlier process with the same
// pid removed, so it never reads another binary's layout.
func publishGRPCGoOffsets(coll *ebpf.Collection, exePath string, pid uint32) {
	m := coll.Maps["grpc_go_offsets"]
	if m == nil || pid == 0 {
		return
	}
	off, ok := resolveGRPCGoFieldOffsets(exePath, pid)
	if !ok {
		_ = m.Delete(pid)
		logger.Debug("Go gRPC: no DWARF framer offsets, pairing falls back to the TCP tuple",
			zap.Uint32("pid", pid))
		return
	}
	if err := m.Update(pid, off, ebpf.UpdateAny); err != nil {
		logger.Debug("Go gRPC: could not publish framer offsets", zap.Uint32("pid", pid), zap.Error(err))
		return
	}
	logger.Debug("Go gRPC: framer offsets published",
		zap.Uint32("pid", pid),
		zap.Uint32("loopy", off.LoopyFramer),
		zap.Uint32("server", off.ServerFramer),
		zap.Uint32("client", off.ClientFramer))
}
