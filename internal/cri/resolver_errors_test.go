package cri

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type erroringRuntimeServer struct {
	runtimeapi.UnimplementedRuntimeServiceServer
}

func (erroringRuntimeServer) ContainerStatus(context.Context, *runtimeapi.ContainerStatusRequest) (*runtimeapi.ContainerStatusResponse, error) {
	return nil, errors.New("container not found")
}

func newErroringResolver(t *testing.T) *Resolver {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	runtimeapi.RegisterRuntimeServiceServer(srv, erroringRuntimeServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop() })

	conn, err := grpc.NewClient(
		"passthrough://bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &Resolver{
		endpoint: "bufnet",
		conn:     conn,
		client:   runtimeapi.NewRuntimeServiceClient(conn),
	}
}

func TestResolveContainer_ContainerStatusErrorWrapped(t *testing.T) {
	r := newErroringResolver(t)
	_, err := r.ResolveContainer(context.Background(), "abc123")
	if err == nil {
		t.Fatal("expected an error when ContainerStatus fails")
	}
	if !strings.Contains(err.Error(), "ContainerStatus failed") {
		t.Errorf("error = %v, want it to wrap the ContainerStatus failure", err)
	}
}

func TestExtractLooseCgroupsPath_DotCollapsesToEmpty(t *testing.T) {
	if got := extractLooseCgroupsPath(`{"cgroupsPath":"."}`); got != "" {
		t.Fatalf("extractLooseCgroupsPath(dot) = %q, want empty", got)
	}
}
