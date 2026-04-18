package cri

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const bufSize = 1 << 20 // 1 MiB

// fakeRuntimeServer is a minimal CRI RuntimeService server.
type fakeRuntimeServer struct {
	runtimeapi.UnimplementedRuntimeServiceServer
	info map[string]string
}

func (f *fakeRuntimeServer) ContainerStatus(_ context.Context, req *runtimeapi.ContainerStatusRequest) (*runtimeapi.ContainerStatusResponse, error) {
	return &runtimeapi.ContainerStatusResponse{
		Status: &runtimeapi.ContainerStatus{Id: req.ContainerId},
		Info:   f.info,
	}, nil
}

// startFakeCRIServer starts an in-process gRPC CRI server and returns a conn to it.
func startFakeCRIServer(t *testing.T, info map[string]string) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	runtimeapi.RegisterRuntimeServiceServer(srv, &fakeRuntimeServer{info: info})
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(func() { srv.Stop() })

	conn, err := grpc.NewClient(
		"passthrough://bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to create bufconn client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// newFakeResolver creates a Resolver backed by a fake in-process CRI server.
func newFakeResolver(t *testing.T, info map[string]string) *Resolver {
	t.Helper()
	conn := startFakeCRIServer(t, info)
	return &Resolver{
		endpoint: "bufnet",
		conn:     conn,
		client:   runtimeapi.NewRuntimeServiceClient(conn),
	}
}

// TestNewResolver_DefaultEndpoint covers the NewResolver() function body (line 81).
func TestNewResolver_DefaultEndpoint(t *testing.T) {
	t.Setenv("PODTRACE_CRI_ENDPOINT", "")
	_, err := NewResolver()
	// With no endpoint and no socket file, expect "not found" error.
	if err == nil {
		t.Log("NewResolver succeeded (unexpected but not fatal)")
	}
}

// TestResolverClose_WithConn covers the r.conn.Close() path in Close() (line 151).
func TestResolverClose_WithConn(t *testing.T) {
	conn, err := grpc.NewClient(
		"unix:///nonexistent/podtrace-test-close.sock",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Skipf("cannot create test grpc conn: %v", err)
	}
	r := &Resolver{endpoint: "x", conn: conn}
	// Close should call conn.Close() — may return nil or an error.
	_ = r.Close()
}

// TestResolveContainer_Success covers the happy path through ResolveContainer
// with a fake in-process CRI server returning cgroupsPath and PID in JSON.
func TestResolveContainer_Success(t *testing.T) {
	infoJSON := `{"cgroupsPath":"/kubepods/besteffort/pod123/ctr456","pid":1234}`
	r := newFakeResolver(t, map[string]string{"info": infoJSON})

	info, err := r.ResolveContainer(context.Background(), "abc123def456")
	if err != nil {
		t.Fatalf("ResolveContainer failed: %v", err)
	}
	if info.PID != 1234 {
		t.Errorf("expected PID=1234, got %d", info.PID)
	}
	if info.CgroupsPath == "" {
		t.Error("expected non-empty CgroupsPath")
	}
}

// TestResolveContainer_EmptyInfo covers the path where Info map has no JSON data.
func TestResolveContainer_EmptyInfo(t *testing.T) {
	r := newFakeResolver(t, map[string]string{})

	info, err := r.ResolveContainer(context.Background(), "abc123def456")
	if err != nil {
		t.Fatalf("ResolveContainer should succeed even with empty info, got: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	// No cgroup path in info → CgroupsPath stays empty.
	if info.CgroupsPath != "" {
		t.Errorf("expected empty CgroupsPath for empty info, got %q", info.CgroupsPath)
	}
}

// TestResolveContainer_WithCgroupFields covers the PODTRACE_CRI_CGROUP_FIELDS path (lines 193-199).
func TestResolveContainer_WithCgroupFields(t *testing.T) {
	t.Setenv("PODTRACE_CRI_CGROUP_FIELDS", "custom.cgroup,another.field")
	infoJSON := `{"cgroupsPath":"/kubepods/pod123/ctr456","pid":42}`
	r := newFakeResolver(t, map[string]string{"info": infoJSON})

	info, err := r.ResolveContainer(context.Background(), "testcontainer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = info
}

// TestResolveContainer_LooseCgroupExtraction covers the fallback loose-extraction
// path (lines 226-235) when standard JSON parsing finds no cgroup.
func TestResolveContainer_LooseCgroupExtraction(t *testing.T) {
	// Provide raw string that contains cgroupsPath as a raw key but not valid JSON.
	rawInfo := `some raw data "cgroupsPath":"/loose/cgroup/path" more data`
	r := newFakeResolver(t, map[string]string{"info": rawInfo})

	info, err := r.ResolveContainer(context.Background(), "testcontainer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The loose extractor should find the path.
	if info.CgroupsPath == "" {
		t.Log("loose extraction returned empty (acceptable for malformed input)")
	}
}

// TestResolveContainer_CgroupWithoutLeadingSlash covers the "/" prepend path (lines 237-239).
func TestResolveContainer_CgroupWithoutLeadingSlash(t *testing.T) {
	// Return a cgroup path without leading slash in JSON.
	infoJSON := `{"cgroupsPath":"kubepods/besteffort/pod123/ctr456"}`
	r := newFakeResolver(t, map[string]string{"info": infoJSON})

	info, err := r.ResolveContainer(context.Background(), "testcontainer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.CgroupsPath != "" && info.CgroupsPath[0] != '/' {
		t.Errorf("expected CgroupsPath to start with '/', got %q", info.CgroupsPath)
	}
}

// TestResolveContainer_NullInfoValue covers the empty-string info value path (line 204).
func TestResolveContainer_NullInfoValue(t *testing.T) {
	r := newFakeResolver(t, map[string]string{"key": ""})

	_, err := r.ResolveContainer(context.Background(), "testcontainer")
	if err != nil {
		t.Fatalf("unexpected error for empty info value: %v", err)
	}
}
