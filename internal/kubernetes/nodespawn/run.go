package nodespawn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	pkgkube "github.com/podtrace/podtrace/internal/kubernetes"
	"github.com/podtrace/podtrace/internal/logger"
)

// RunOptions drives the per-CLI-invocation orchestration: figure out which
// nodes host the targets, spawn one privileged pod on each, stream their
// output, and clean up on exit.
type RunOptions struct {
	Clientset  kubernetes.Interface
	RestConfig *rest.Config

	Selection pkgkube.TargetSelection

	Image            string
	ImagePullPolicy  corev1.PullPolicy
	ImagePullSecrets []corev1.LocalObjectReference

	SpawnNamespace string

	ActiveDeadlineSeconds int64

	BuildChildArgs func(nodeName string, pods []PodRef) []string

	OwnerHost string
	OwnerPID  int

	ServiceAccountName string

	Streams genericiooptions.IOStreams

	OnPodRunning func(ctx context.Context, pod *corev1.Pod) error

	DynamicReSpawn bool
	PollInterval   time.Duration

	KeepSpawnPodOnFailure bool
}

// Run orchestrates the spawn + stream lifecycle. It returns when every per-node
// pod has terminated or ctx is cancelled.
func Run(ctx context.Context, opts RunOptions) error {
	if opts.Clientset == nil || opts.RestConfig == nil {
		return fmt.Errorf("nodespawn: Clientset and RestConfig required")
	}
	if opts.Image == "" {
		return fmt.Errorf("nodespawn: Image required")
	}
	if opts.BuildChildArgs == nil {
		return fmt.Errorf("nodespawn: BuildChildArgs callback required")
	}

	nodes, err := ResolveTargetNodes(ctx, opts.Clientset, opts.Selection)
	if err != nil {
		return err
	}
	if nodes.Empty() {
		return fmt.Errorf("nodespawn: no scheduled target pods")
	}

	if opts.ActiveDeadlineSeconds <= 0 {
		opts.ActiveDeadlineSeconds = 3600
	}

	multiNode := len(nodes.NodeNames) > 1

	g, gctx := errgroup.WithContext(ctx)
	var wmu sync.Mutex
	var cmu sync.Mutex
	covered := map[string]bool{}

	startNode := func(node string, podRefs []PodRef, tols []corev1.Toleration) error {
		cmu.Lock()
		if covered[node] {
			cmu.Unlock()
			return nil
		}
		covered[node] = true
		cmu.Unlock()
		ns := opts.SpawnNamespace
		if ns == "" {
			ns = podRefs[0].Namespace
		}
		args := opts.BuildChildArgs(node, podRefs)
		podSpec, err := BuildPodSpec(PodSpecOptions{
			NodeName:              node,
			Namespace:             ns,
			Image:                 opts.Image,
			ImagePullPolicy:       opts.ImagePullPolicy,
			ImagePullSecrets:      opts.ImagePullSecrets,
			Args:                  args,
			ActiveDeadlineSeconds: opts.ActiveDeadlineSeconds,
			Tolerations:           tols,
			ServiceAccountName:    opts.ServiceAccountName,
			OwnerHost:             opts.OwnerHost,
			OwnerPID:              opts.OwnerPID,
		})
		if err != nil {
			cmu.Lock()
			delete(covered, node)
			cmu.Unlock()
			return err
		}
		label := nodePodLabel(podRefs)
		g.Go(func() error {
			return runOneNode(gctx, opts, podSpec, multiNode, &wmu, label)
		})
		return nil
	}

	for _, node := range nodes.NodeNames {
		if err := startNode(node, nodes.ByNode[node], nodes.TolerationsByNode[node]); err != nil {
			return err
		}
	}

	if opts.DynamicReSpawn {
		interval := opts.PollInterval
		if interval <= 0 {
			interval = 30 * time.Second
		}
		g.Go(func() error {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-gctx.Done():
					return nil
				case <-t.C:
				}
				poll, err := ResolveTargetNodes(gctx, opts.Clientset, opts.Selection)
				if err != nil {
					continue
				}
				for _, n := range poll.NodeNames {
					cmu.Lock()
					already := covered[n]
					cmu.Unlock()
					if already {
						continue
					}
					if err := startNode(n, poll.ByNode[n], poll.TolerationsByNode[n]); err != nil {
						return err
					}
				}
			}
		})
	}

	return g.Wait()
}

func nodePodLabel(podRefs []PodRef) string {
	seen := map[string]struct{}{}
	var names []string
	for _, p := range podRefs {
		if p.Name == "" {
			continue
		}
		if _, ok := seen[p.Name]; ok {
			continue
		}
		seen[p.Name] = struct{}{}
		names = append(names, p.Name)
	}
	if len(names) == 0 {
		return ""
	}
	label := strings.Join(names, ",")
	const maxLen = 60
	if len(label) > maxLen {
		label = label[:maxLen-1] + "…"
	}
	return label
}

func runOneNode(ctx context.Context, opts RunOptions, podSpec *corev1.Pod, multiNode bool, wmu *sync.Mutex, nodeLabel string) (retErr error) {
	created, err := opts.Clientset.CoreV1().Pods(podSpec.Namespace).Create(ctx, podSpec, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsForbidden(err) && strings.Contains(err.Error(), "violates PodSecurity") {
			return fmt.Errorf("spawn pod admission rejected by PodSecurity in namespace %q. "+
				"Remediation: kubectl label ns/%s pod-security.kubernetes.io/enforce=privileged --overwrite\n  (or use --spawn-namespace to point at a namespace that allows privileged pods). "+
				"Underlying error: %w", podSpec.Namespace, podSpec.Namespace, err)
		}
		return fmt.Errorf("create spawn pod %s/%s: %w", podSpec.Namespace, podSpec.Name, err)
	}
	logger.Debug("Spawn pod created",
		zap.String("namespace", created.Namespace),
		zap.String("name", created.Name),
		zap.String("node", podSpec.Spec.NodeSelector["kubernetes.io/hostname"]))

	cleanupCtx, cancelCleanup := context.WithCancel(context.Background())
	defer cancelCleanup()
	defer func() {
		if retErr != nil && opts.KeepSpawnPodOnFailure {
			_, _ = fmt.Fprintf(opts.Streams.ErrOut,
				"spawn pod preserved for debugging: kubectl -n %s logs %s (reaper will clean it up on the next podtrace invocation)\n",
				created.Namespace, created.Name)
			logger.Debug("Spawn pod kept on failure",
				zap.String("namespace", created.Namespace),
				zap.String("name", created.Name))
			return
		}
		_ = DeletePod(cleanupCtx, opts.Clientset, created.Namespace, created.Name)
	}()

	running, err := waitForPodRunningOrTerminated(ctx, opts.Clientset, created.Namespace, created.Name)
	if err != nil {
		return err
	}
	logger.Debug("Spawn pod reached terminal-or-running state",
		zap.String("namespace", running.Namespace),
		zap.String("name", running.Name),
		zap.String("state", string(running.Status.Phase)))

	if opts.OnPodRunning != nil {
		if cbErr := opts.OnPodRunning(ctx, running); cbErr != nil {
			return cbErr
		}
	}

	streams := opts.Streams
	if multiNode {
		host := podSpec.Spec.NodeSelector["kubernetes.io/hostname"]
		tag := host
		if nodeLabel != "" {
			tag = host + ": " + nodeLabel
		}
		streams.Out = newPrefixedWriter(streams.Out, "["+tag+"] ", wmu)
		streams.ErrOut = newPrefixedWriter(streams.ErrOut, "["+tag+"] ", wmu)
		streams.In = nil
	}

	if _, err := AttachToPod(ctx, opts.RestConfig, opts.Clientset, running, streams); err != nil {
		diag := diagnoseAttachFailure(cleanupCtx, opts.Clientset, running.Namespace, running.Name, err)
		var afe *AttachFailedError
		if errors.As(diag, &afe) && afe.ExitCode != nil {
			logger.Debug("Spawn container exited before attach completed",
				zap.String("namespace", afe.Namespace),
				zap.String("name", afe.PodName),
				zap.Int32("exit_code", *afe.ExitCode),
				zap.String("reason", afe.Reason),
				zap.String("termination_message", afe.Message))
		}
		return diag
	}

	exit := WaitForExitCode(ctx, opts.Clientset, running.Namespace, running.Name)
	if exit != 0 {
		if tail := dumpPodLogs(cleanupCtx, opts.Clientset, running.Namespace, running.Name); tail != "" {
			_, _ = fmt.Fprintf(opts.Streams.ErrOut, "spawn pod %s/%s tail:\n%s\n", running.Namespace, running.Name, tail)
		}
		return &ExitError{Code: int(exit), Node: podSpec.Spec.NodeSelector["kubernetes.io/hostname"]}
	}
	return nil
}

// dumpPodLogsCap bounds how much pod stderr we read into the error message.
const dumpPodLogsCap = 64 * 1024

// dumpPodLogs returns the spawned pod's last log lines on a best-effort basis;
// errors are swallowed because this runs on the failure path and shouldn't
// itself fail.
var dumpPodLogs = func(ctx context.Context, clientset kubernetes.Interface, namespace, name string) string {
	req := clientset.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{TailLines: ptrInt64(50)})
	rc, err := req.Stream(ctx)
	if err != nil {
		return ""
	}
	defer func() { _ = rc.Close() }()
	out, _ := io.ReadAll(io.LimitReader(rc, dumpPodLogsCap))
	return string(out)
}

func ptrInt64(v int64) *int64 { return &v }

// ExitError carries a non-zero exit code from a spawned pod so the CLI can
// propagate the same code to its caller.
type ExitError struct {
	Code int
	Node string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("spawn pod on node %q exited with code %d", e.Node, e.Code)
}

// prefixedWriter wraps an io.Writer with a per-line prefix and a shared lock
// so multi-node streams interleave cleanly.
type prefixedWriter struct {
	out    io.Writer
	prefix string
	mu     *sync.Mutex
	buf    []byte
}

func newPrefixedWriter(out io.Writer, prefix string, mu *sync.Mutex) *prefixedWriter {
	return &prefixedWriter{out: out, prefix: prefix, mu: mu}
}

func (w *prefixedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := indexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := w.buf[:i+1]
		if _, err := w.out.Write([]byte(w.prefix)); err != nil {
			return len(p), err
		}
		if _, err := w.out.Write(line); err != nil {
			return len(p), err
		}
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

func indexByte(b []byte, c byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// HostnameFromEnv returns the workstation hostname, useful for stamping into
// owner-host labels at the CLI layer.
func HostnameFromEnv() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return Hostname()
}
