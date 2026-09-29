package probes

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/config"
)

func placeELF(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	dst, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
}

func fakeProcTree(t *testing.T, pid uint32, libs ...string) {
	t.Helper()
	base := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = base
	t.Cleanup(func() { config.ProcBasePath = orig })
	proc := filepath.Join(base, fmt.Sprint(pid))
	placeELF(t, filepath.Join(proc, "exe"))
	for _, lib := range libs {
		placeELF(t, filepath.Join(proc, "root", lib))
	}
}

func placeholderPrograms(names ...string) *ebpf.Collection {
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{}}
	for _, n := range names {
		coll.Programs[n] = &ebpf.Program{}
	}
	return coll
}

func TestLibraryProbesOpenEveryLibraryTheyFind(t *testing.T) {
	const pid = 4242
	lib := "usr/lib/x86_64-linux-gnu/"
	fakeProcTree(t, pid,
		lib+"libpq.so.5", lib+"libmysqlclient.so.21",
		lib+"libhiredis.so.1", lib+"libmemcached.so.11", lib+"librdkafka.so.1",
		lib+"libnghttp3.so.9")
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{}}
	for name, attach := range map[string]func() int{
		"db":        func() int { return len(AttachDBProbesWithPID(coll, "", pid, NewAttachedFiles())) },
		"redis":     func() int { return len(AttachRedisProbesWithPID(coll, "", pid, NewAttachedFiles())) },
		"memcached": func() int { return len(AttachMemcachedProbesWithPID(coll, "", pid, NewAttachedFiles())) },
		"kafka":     func() int { return len(AttachKafkaProbesWithPID(coll, "", pid, NewAttachedFiles())) },
		"nghttp3": func() int {
			return len(AttachNghttp3Probes(placeholderPrograms("uprobe_nghttp3_submit_request"), pid, NewAttachedFiles()))
		},
	} {
		if n := attach(); n != 0 {
			t.Errorf("%s attached %d links from placeholder programs", name, n)
		}
	}
}

func TestGoBinaryProbesOpenTheProcessExecutable(t *testing.T) {
	const pid = 4243
	fakeProcTree(t, pid)
	coll := placeholderPrograms("uprobe_go_tls_write", "uprobe_go_tls_read", "uprobe_go_tls_read_ret",
		"uprobe_grpc_go_write_header", "uprobe_go_db_conn", "uprobe_go_db_conn_ret")
	exe := filepath.Join(config.ProcBasePath, fmt.Sprint(pid), "exe")
	total := len(AttachGoTLSProbes(coll, pid)) + len(AttachGoGRPCProbes(coll, pid)) +
		len(AttachGoHTTP3Probes(coll, pid)) + len(attachGoAcquireProbes(coll, exe, pid)) +
		len(attachSSLByOffset(placeholderPrograms("uprobe_SSL_write"), exe, sslOffsets{}))
	if total != 0 {
		t.Errorf("attached %d links from placeholder programs", total)
	}
}
