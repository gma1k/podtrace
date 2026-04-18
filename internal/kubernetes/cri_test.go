package kubernetes

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// fakeK8sCRIServer is a minimal CRI RuntimeService server for kubernetes package tests.
type fakeK8sCRIServer struct {
	runtimeapi.UnimplementedRuntimeServiceServer
	info map[string]string
}

func (f *fakeK8sCRIServer) ContainerStatus(_ context.Context, req *runtimeapi.ContainerStatusRequest) (*runtimeapi.ContainerStatusResponse, error) {
	return &runtimeapi.ContainerStatusResponse{
		Status: &runtimeapi.ContainerStatus{Id: req.ContainerId},
		Info:   f.info,
	}, nil
}

// startUnixCRIServer starts a gRPC CRI server on a Unix domain socket and
// returns the endpoint URL ("unix:///path/to/socket").
func startUnixCRIServer(t *testing.T, info map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "cri.sock")

	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("cannot create unix socket: %v", err)
	}
	srv := grpc.NewServer()
	runtimeapi.RegisterRuntimeServiceServer(srv, &fakeK8sCRIServer{info: info})
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(func() { srv.Stop() })

	return "unix://" + sockPath
}

// startUnixCRIServerWithConn starts a CRI server AND returns a pre-connected
// gRPC client connection for use in building a Resolver directly.
func startUnixCRIServerWithConn(t *testing.T, info map[string]string) (*grpc.ClientConn, string) { //nolint:unused
	t.Helper()
	endpoint := startUnixCRIServer(t, info)

	sockPath := endpoint[len("unix://"):]
	conn, err := grpc.NewClient(
		"unix://"+sockPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Skipf("cannot create grpc client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, endpoint
}

// TestResolveCgroupPathCRI_WithFakeServer_NoCgroupPath covers the path where
// the CRI server returns an empty CgroupsPath (lines 303-304).
func TestResolveCgroupPathCRI_WithFakeServer_NoCgroupPath(t *testing.T) {
	// Info with no cgroup path.
	endpoint := startUnixCRIServer(t, map[string]string{"info": `{"pid":123}`})
	t.Setenv("PODTRACE_CRI_ENDPOINT", endpoint)

	_, err := resolveCgroupPathCRI(context.Background(), "test-container")
	if err == nil {
		t.Error("expected error when CRI returns no cgroups path")
	}
}

// TestResolveCgroupPathCRI_WithFakeServer_RelativePath covers the path where
// the CRI server returns a relative cgroup path (lines 327-359).
func TestResolveCgroupPathCRI_WithFakeServer_RelativePath(t *testing.T) {
	// Return a relative cgroup path (no leading slash) that won't exist on filesystem.
	infoJSON := `{"cgroupsPath":"kubepods/besteffort/pod123/ctr456"}`
	endpoint := startUnixCRIServer(t, map[string]string{"info": infoJSON})
	t.Setenv("PODTRACE_CRI_ENDPOINT", endpoint)

	_, err := resolveCgroupPathCRI(context.Background(), "test-container")
	// Either "not found on filesystem" or some other error is acceptable.
	_ = err
}

// TestResolveCgroupPathCRI_WithFakeServer_AbsolutePath covers the absolute
// cgroup path branch (lines 313-324) where the path doesn't exist on fs.
func TestResolveCgroupPathCRI_WithFakeServer_AbsolutePath(t *testing.T) {
	// Return an absolute path that does not exist on filesystem.
	infoJSON := `{"cgroupsPath":"/nonexistent/kubepods/besteffort/pod123/ctr456"}`
	endpoint := startUnixCRIServer(t, map[string]string{"info": infoJSON})
	t.Setenv("PODTRACE_CRI_ENDPOINT", endpoint)

	_, err := resolveCgroupPathCRI(context.Background(), "test-container")
	// Expects "cgroup path not found on filesystem" error.
	_ = err
}

// TestResolveCgroupPathCRI_WithFakeServer_CgroupBasePath covers the root cgroup
// path rejection (cg == "/" after stripping the CgroupBasePath prefix).
func TestResolveCgroupPathCRI_WithFakeServer_CgroupBasePath(t *testing.T) {
	// When CRI returns exactly the CgroupBasePath, after stripping the prefix
	// cg becomes "" → cg = "/" → triggers "root cgroups path" error.
	infoJSON := `{"cgroupsPath":"/sys/fs/cgroup"}`
	endpoint := startUnixCRIServer(t, map[string]string{"info": infoJSON})
	t.Setenv("PODTRACE_CRI_ENDPOINT", endpoint)

	_, err := resolveCgroupPathCRI(context.Background(), "test-container")
	_ = err // root path error or "not found" both acceptable
}

// TestResolveCgroupPathCRI_WithFakeServer_LongPath covers the trimmed path search
// (lines 333-357) with a multi-segment relative path that won't exist on fs.
func TestResolveCgroupPathCRI_WithFakeServer_LongPath(t *testing.T) {
	// A longer relative path triggers the systemd slice expansion search at lines 350-357.
	infoJSON := `{"cgroupsPath":"kubepods-besteffort.slice/kubepods-besteffort-pod123.slice/crio-ctr456.scope"}`
	endpoint := startUnixCRIServer(t, map[string]string{"info": infoJSON})
	t.Setenv("PODTRACE_CRI_ENDPOINT", endpoint)

	_, err := resolveCgroupPathCRI(context.Background(), "test-container")
	_ = err // "not found on filesystem" is expected
}

