//go:build bpf_loadtest && linux

package tracer

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

const restartWorkerEnv = "PODTRACE_RESTART_WORKER"

func TestKernelRestartWorker(t *testing.T) {
	if os.Getenv(restartWorkerEnv) == "" {
		t.Skip("only runs as the child of the restart error kernel test")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Println("socket", err)
		syscall.Exit(1)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		fmt.Println("bind", err)
		syscall.Exit(1)
	}
	closed, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Println("socket", err)
		syscall.Exit(1)
	}
	if err := syscall.Bind(closed, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		fmt.Println("bind", err)
		syscall.Exit(1)
	}
	sa, err := syscall.Getsockname(closed)
	if err != nil {
		fmt.Println("getsockname", err)
		syscall.Exit(1)
	}
	_ = syscall.Close(closed)
	if err := syscall.Connect(fd, sa); err != nil {
		fmt.Println("connect", err)
		syscall.Exit(1)
	}
	fmt.Println("ready")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	if _, err := syscall.Write(fd, []byte("x")); err != nil {
		fmt.Println("write", err)
		syscall.Exit(1)
	}
	buf := make([]byte, 64)
	if _, _, err := syscall.Recvfrom(fd, buf, 0); err != syscall.ECONNREFUSED {
		fmt.Println("refused", err)
		syscall.Exit(1)
	}
	fmt.Println("blocking")
	_, _, _ = syscall.Recvfrom(fd, buf, 0)
	syscall.Exit(0)
}

func TestKernelAReceiveInterruptedByExitIsNotAnAggregatedError(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	dir := fmt.Sprintf("/sys/fs/cgroup/podtrace-restart-%d", os.Getpid())
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Skipf("cannot create a cgroup for the worker: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}

	tr, err := NewTracer()
	if err != nil {
		t.Skipf("cannot load the podtrace object here: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tr.Start(ctx, make(chan *events.Event, 1<<14)); err != nil {
		t.Fatal(err)
	}
	if err := tr.SetCgroups([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if err := tr.SetKernelAggregationMode(kernelagg.ModeOn); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestKernelRestartWorker$")
	cmd.Env = append(os.Environ(), restartWorkerEnv+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(out)
	if !sc.Scan() || sc.Text() != "ready" {
		_ = cmd.Process.Kill()
		t.Fatalf("worker did not start: %q", sc.Text())
	}
	if err := os.WriteFile(dir+"/cgroup.procs", []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		_ = cmd.Process.Kill()
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte("go\n")); err != nil {
		t.Fatal(err)
	}
	if !sc.Scan() || sc.Text() != "blocking" {
		_ = cmd.Process.Kill()
		t.Fatalf("worker did not reach the blocking receive: %q", sc.Text())
	}
	time.Sleep(200 * time.Millisecond)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	time.Sleep(200 * time.Millisecond)

	rows, err := tr.DrainKernelMetrics()
	if err != nil {
		t.Fatal(err)
	}
	var failed, clean uint64
	for _, r := range rows {
		if r.Key.CgroupID != st.Ino || events.EventType(r.Key.EventType) != events.EventUDPRecv {
			continue
		}
		if kernelagg.DecodeVariant(r.Key.Variant).IsError {
			failed += r.Value.Count
		} else {
			clean += r.Value.Count
		}
	}
	if failed != 1 {
		t.Errorf("%d receives counted as errors, want 1: the one the closed port refused", failed)
	}
	if clean != 1 {
		t.Errorf("%d receives counted as clean, want 1: the one the exit interrupted with ERESTARTSYS", clean)
	}
}
