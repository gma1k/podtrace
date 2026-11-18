//go:build bpf_loadtest && linux

package tracer

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/loader"
)

func TestTracerCollectionLoadsOnRunningKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel BPF load requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}
	original := config.BPFObjectPath
	t.Cleanup(func() { config.BPFObjectPath = original })
	config.BPFObjectPath = filepath.Join("..", "embedded", "podtrace."+runtime.GOARCH+".bpf.o")
	if path := os.Getenv("PODTRACE_BPF_OBJECT"); path != "" {
		config.BPFObjectPath = path
	}

	spec, err := loader.LoadPodtrace()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	names := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		names = append(names, name)
	}

	coll, uprobeMulti, err := loadCollection(spec, ebpf.CollectionOptions{}, false)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			summary, _, _ := strings.Cut(err.Error(), "\n")
			t.Fatalf("kernel rejected the collection: %.300s\n%+v", summary, ve)
		}
		t.Fatalf("load collection: %v", err)
	}
	defer coll.Close()

	var pruned []string
	for _, name := range names {
		if strings.HasSuffix(name, compatSuffix) {
			continue
		}
		if coll.Programs[name] == nil {
			pruned = append(pruned, name)
		}
	}
	sort.Strings(pruned)
	t.Logf("loaded %d of %d programs (uprobe_multi=%v); pruned for this kernel: %v",
		len(coll.Programs), len(names), uprobeMulti, pruned)
	for _, name := range []string{
		"tracepoint_oom_mark_victim",
		"sockops_rtt",
		"tracepoint_inet_sock_set_state",
		"kprobe_tcp_sendmsg",
	} {
		if coll.Programs[name] == nil {
			t.Errorf("program %s was not loaded", name)
		}
	}
}
