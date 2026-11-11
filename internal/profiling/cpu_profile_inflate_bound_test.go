package profiling

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func gzipped(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestAGzipBombCPUProfileIsRefusedAtTheInflateCap(t *testing.T) {
	bomb := gzipped(t, make([]byte, maxDecompressedCPUProfileBytes+1))
	if len(bomb) > 1<<20 {
		t.Fatalf("bomb is %d bytes compressed, the fixture should be small", len(bomb))
	}
	_, err := parseCPUProfile(bomb)
	if err == nil || !strings.Contains(err.Error(), "inflates past") {
		t.Errorf("parseCPUProfile = %v, want an inflate-cap error", err)
	}
}

func TestAProfileInflatingExactlyToTheCapIsKept(t *testing.T) {
	plain := bytes.Repeat([]byte{7}, 4096)
	got, err := inflateProfile(gzipped(t, plain), int64(len(plain)))
	if err != nil || !bytes.Equal(got, plain) {
		t.Errorf("inflateProfile = %d bytes, %v; want the %d plain bytes", len(got), err, len(plain))
	}
	if _, err := inflateProfile(gzipped(t, plain), int64(len(plain)-1)); err == nil {
		t.Error("a profile one byte past the cap was accepted")
	}
}

func TestAGzippedCPUProfileStillParses(t *testing.T) {
	raw := cpuProfileBytes(t)
	if raw[0] != 0x1f || raw[1] != 0x8b {
		raw = gzipped(t, raw)
	}
	top, err := parseCPUProfile(raw)
	if err != nil || len(top) == 0 || top[0].Function != "main.hot" {
		t.Errorf("parseCPUProfile = %v, %v; want main.hot first", top, err)
	}
}

func TestAnUncompressedCPUProfileStillParses(t *testing.T) {
	raw := cpuProfileBytes(t)
	plain, err := inflateProfile(raw, maxDecompressedCPUProfileBytes)
	if err != nil {
		t.Fatal(err)
	}
	top, err := parseCPUProfile(plain)
	if err != nil || len(top) == 0 || top[0].Function != "main.hot" {
		t.Errorf("parseCPUProfile = %v, %v; want main.hot first", top, err)
	}
}

func TestACorruptGzipCPUProfileIsAnError(t *testing.T) {
	if _, err := inflateProfile([]byte{0x1f, 0x8b, 0, 0}, 1<<20); err == nil {
		t.Error("a truncated gzip header was accepted")
	}
	truncated := gzipped(t, bytes.Repeat([]byte("x"), 1<<16))
	if _, err := inflateProfile(truncated[:len(truncated)-12], 1<<20); err == nil {
		t.Error("a gzip stream cut short was accepted")
	}
}
