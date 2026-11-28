package safeelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	buildInfoAddr = 0x500000
	rodataAddr    = 0x600000
)

func buildInfoHeader(ptrSize, flags byte, versionPointer uint64, order binary.ByteOrder) []byte {
	h := make([]byte, goBuildInfoHeaderSize)
	copy(h, goBuildInfoMagic)
	h[14] = ptrSize
	h[15] = flags
	if ptrSize == 4 {
		order.PutUint32(h[16:], u32(versionPointer))
	} else {
		order.PutUint64(h[16:], versionPointer)
	}
	return h
}

func inlineBuildInfo(version string) []byte {
	b := buildInfoHeader(8, 2, 0, binary.LittleEndian)
	b = binary.AppendUvarint(b, uint64(len(version)))
	return append(b, version...)
}

func goVersionOf(t *testing.T, secs ...rawSection) (string, bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exe")
	if err := os.WriteFile(path, buildELF(elf.ELFCLASS64, secs), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	return GoVersion(f)
}

func buildInfoSection(data []byte) rawSection {
	return rawSection{name: ".go.buildinfo", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC, addr: buildInfoAddr, load: true, data: data}
}

func stringHeader(order binary.AppendByteOrder, ptrSize int, data, length uint64) []byte {
	if ptrSize == 4 {
		return order.AppendUint32(order.AppendUint32(nil, u32(data)), u32(length))
	}
	return order.AppendUint64(order.AppendUint64(nil, data), length)
}

func TestGoVersionOfThisBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find test executable: %v", err)
	}
	f, err := Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if got, ok := GoVersion(f); !ok || got != runtime.Version() {
		t.Fatalf("GoVersion = (%q, %v), want %q", got, ok, runtime.Version())
	}
}

func TestGoVersionStoredInline(t *testing.T) {
	if got, ok := goVersionOf(t, buildInfoSection(inlineBuildInfo("go1.26.2"))); !ok || got != "go1.26.2" {
		t.Fatalf("GoVersion = (%q, %v), want go1.26.2", got, ok)
	}
}

func TestGoVersionStoredBehindPointers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order interface {
			binary.ByteOrder
			binary.AppendByteOrder
		}
		ptrSize byte
		flags   byte
	}{
		{"64-bit little-endian", binary.LittleEndian, 8, 0},
		{"32-bit big-endian", binary.BigEndian, 4, 1},
	} {
		rodata := stringHeader(tc.order, int(tc.ptrSize), rodataAddr+32, 8)
		rodata = append(rodata, make([]byte, 32-len(rodata))...)
		rodata = append(rodata, "go1.17.3"...)
		got, ok := goVersionOf(t,
			buildInfoSection(buildInfoHeader(tc.ptrSize, tc.flags, rodataAddr, tc.order)),
			rawSection{name: ".rodata", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC, addr: rodataAddr, load: true, data: rodata})
		if !ok || got != "go1.17.3" {
			t.Errorf("%s: GoVersion = (%q, %v), want go1.17.3", tc.name, got, ok)
		}
	}
}

func TestGoVersionFindsTheAlignedMagic(t *testing.T) {
	data := make([]byte, 8)
	data = append(data, goBuildInfoMagic...)
	data = append(data, make([]byte, 32-len(data))...)
	data = append(data, inlineBuildInfo("go1.25.0")...)
	if got, ok := goVersionOf(t, buildInfoSection(data)); !ok || got != "go1.25.0" {
		t.Fatalf("GoVersion = (%q, %v), want the version after the aligned magic", got, ok)
	}
}

func TestGoVersionRefusesAnInlineLengthPastTheCap(t *testing.T) {
	b := buildInfoHeader(8, 2, 0, binary.LittleEndian)
	b = binary.AppendUvarint(b, 900<<20)
	b = append(b, bytes.Repeat([]byte{'x'}, MaxGoVersionLength+1)...)
	if got, ok := goVersionOf(t, buildInfoSection(b)); ok {
		t.Fatalf("GoVersion = %d bytes, want a version string claiming 900 MiB refused", len(got))
	}
}

func TestGoVersionRefusesMalformedBuildInfo(t *testing.T) {
	le := binary.LittleEndian
	oversized := stringHeader(le, 8, rodataAddr+16, MaxGoVersionLength+1)
	unreachableString := stringHeader(le, 8, 0x900000, 8)
	pastSegment := stringHeader(le, 8, rodataAddr+(1<<20)-8, 8)
	rodata := func(b []byte) rawSection {
		return rawSection{name: ".rodata", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC, addr: rodataAddr, load: true, data: b}
	}
	truncated := rodata(pastSegment)
	truncated.declared = 1 << 20

	for _, tc := range []struct {
		name string
		secs []rawSection
	}{
		{"no section", nil},
		{"no file data", []rawSection{{name: ".go.buildinfo", typ: elf.SHT_NOBITS, declared: 64}}},
		{"no magic", []rawSection{buildInfoSection(make([]byte, 64))}},
		{"magic without a whole header", []rawSection{buildInfoSection(append(append([]byte{}, goBuildInfoMagic...), 0, 0))}},
		{"empty inline version", []rawSection{buildInfoSection(inlineBuildInfo(""))}},
		{"inline length cut short", []rawSection{buildInfoSection(append(buildInfoHeader(8, 2, 0, le), 0x80))}},
		{"inline length past the section", []rawSection{buildInfoSection(append(buildInfoHeader(8, 2, 0, le), 10, 'g', 'o'))}},
		{"pointer size 3", []rawSection{buildInfoSection(buildInfoHeader(3, 0, rodataAddr, le))}},
		{"string header outside every segment", []rawSection{buildInfoSection(buildInfoHeader(8, 0, 0x900000, le))}},
		{"string length past the cap", []rawSection{buildInfoSection(buildInfoHeader(8, 0, rodataAddr, le)), rodata(oversized)}},
		{"string outside every segment", []rawSection{buildInfoSection(buildInfoHeader(8, 0, rodataAddr, le)), rodata(unreachableString)}},
		{"segment longer than the file", []rawSection{buildInfoSection(buildInfoHeader(8, 0, rodataAddr, le)), truncated}},
	} {
		if got, ok := goVersionOf(t, tc.secs...); ok {
			t.Errorf("%s: GoVersion = %q, want no version", tc.name, got)
		}
	}
}
