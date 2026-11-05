package probes

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
)

var (
	grpcFixtureOnce sync.Once
	grpcFixtureBin  string
	grpcFixtureErr  error
)

func grpcFixtureBinary(t *testing.T) string {
	t.Helper()
	grpcFixtureOnce.Do(func() {
		goTool, err := exec.LookPath("go")
		if err != nil {
			grpcFixtureErr = err
			return
		}
		dir, err := os.MkdirTemp("", "probesgrpcfix")
		if err != nil {
			grpcFixtureErr = err
			return
		}
		bin := filepath.Join(dir, "grpcfixture")
		cmd := exec.Command(goTool, "build", "-o", bin, "./testdata/grpcfixture")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			grpcFixtureErr = fmt.Errorf("go build: %v\n%s", err, out)
			return
		}
		grpcFixtureBin = bin
	})
	if grpcFixtureErr != nil {
		t.Skipf("cannot build the grpc-go fixture binary: %v", grpcFixtureErr)
	}
	return grpcFixtureBin
}

func TestGRPCGoFramerOffsetsComeFromDWARF(t *testing.T) {
	d, cleanup, idx := fixtureDWARF(t)
	defer cleanup()
	got, ok := grpcGoOffsetsFromDWARF(d, idx, "main.")
	if !ok {
		t.Fatal("framer offsets not resolved from the fixture's grpc-shaped receivers")
	}
	want := grpcGoFieldOffsets{LoopyFramer: 40, ServerFramer: 112, ClientFramer: 24}
	if got != want {
		t.Fatalf("offsets = %+v, want %+v", got, want)
	}
}

func TestGRPCGoFramerOffsetsNeedAllThreeReceivers(t *testing.T) {
	d, cleanup, idx := fixtureDWARF(t)
	defer cleanup()
	for _, pkg := range []string{grpcTransportPackage, "main.loopyOnly", "main.noClient"} {
		if _, ok := grpcGoOffsetsFromDWARF(d, idx, pkg); ok {
			t.Errorf("receivers under %q are incomplete and must not publish offsets", pkg)
		}
	}
}

func TestGRPCGoFramerOffsetsNeedAPointerFramerField(t *testing.T) {
	d, cleanup, idx := fixtureDWARF(t)
	defer cleanup()
	for _, pkg := range []string{"main.noFramer", "main.valueFramer"} {
		if _, ok := grpcGoOffsetsFromDWARF(d, idx, pkg); ok {
			t.Errorf("a loopyWriter under %q without a *framer field must not publish offsets", pkg)
		}
	}
}

func TestGRPCGoFramerOffsetsResolveFromARealGRPCBinary(t *testing.T) {
	bin := grpcFixtureBinary(t)
	got, ok := resolveGRPCGoFieldOffsets(bin, 0)
	if !ok {
		t.Fatal("framer offsets not resolved from a binary linking grpc-go")
	}
	if got.LoopyFramer == 0 || got.ServerFramer == 0 || got.ClientFramer == 0 {
		t.Fatalf("offsets = %+v, every receiver holds its framer after other fields", got)
	}
}

func TestGRPCGoFramerOffsetsAbsentWithoutGRPCOrABinary(t *testing.T) {
	if _, ok := resolveGRPCGoFieldOffsets(goFixtureBinary(t), 0); ok {
		t.Error("a binary without grpc-go must not resolve offsets")
	}
	if _, ok := resolveGRPCGoFieldOffsets(filepath.Join(t.TempDir(), "missing"), 0); ok {
		t.Error("a missing binary must not resolve offsets")
	}
}

func TestGRPCGoOffsetsNeedTheOffsetsMap(t *testing.T) {
	publishGRPCGoOffsets(&ebpf.Collection{Maps: map[string]*ebpf.Map{}}, grpcFixtureBinary(t), 1)
}
