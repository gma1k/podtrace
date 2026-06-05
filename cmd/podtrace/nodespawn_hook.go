package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/podtrace/podtrace/internal/config"
	pkgkube "github.com/podtrace/podtrace/internal/kubernetes"
	"github.com/podtrace/podtrace/internal/kubernetes/nodespawn"
	"github.com/podtrace/podtrace/internal/logger"
	"go.uber.org/zap"
)

// spawnControlFlags are stripped when reconstructing the child argv; they only
// make sense on the workstation. --metrics is also stripped (with a warning)
// because the in-pod port can't be reached from the user's machine.
var spawnControlFlags = map[string]struct{}{
	"local":            {},
	"image":            {},
	"spawn-namespace":  {},
	"service-account":  {},
	"dynamic-spawn":    {},
	"keep-spawn-pod":   {},
	"namespace":        {},
	"namespaces":       {},
	"pods":             {},
	"pod-selector":     {},
	"all-in-namespace": {},
	"app":              {},
	"label":            {},
	"all-namespaces":   {},
}

// maybeSpawnOnNode runs the spawn flow when appropriate. The boolean return
// reports whether the spawn flow handled the invocation.
func maybeSpawnOnNode(ctx context.Context, cmd *cobra.Command, resolver pkgkube.PodResolverInterface, selection pkgkube.TargetSelection) (handled bool, err error) {
	if os.Getenv(nodespawn.EnvNodeLocalSentinel) == "1" {
		return false, nil
	}
	if localMode {
		return false, nil
	}
	if _, err := rest.InClusterConfig(); err == nil {
		return false, nil
	}

	clientset, restCfg, ok := clusterHandles(resolver)
	if !ok {
		return false, nil
	}

	if !selectionIsSpawnable(selection) {
		return false, nil
	}

	image, warnDev := nodespawn.ResolveImage(nodespawn.ResolveImageOptions{
		Override: spawnImage,
		Version:  config.GetVersion(),
	})
	if warnDev {
		logger.Warn("Using fallback image tag :latest; pin a real version via --image or PODTRACE_IMAGE",
			zap.String("image", image))
	}

	ns := spawnNamespace
	if ns == "" {
		ns = os.Getenv("PODTRACE_SPAWN_NAMESPACE")
	}

	host := nodespawn.HostnameFromEnv()
	if _, err := nodespawn.ReapStale(ctx, clientset, ns, host); err != nil {
		logger.Debug("Reaper failed (non-fatal)", zap.Error(err))
	}

	preResolved, err := nodespawn.ResolveTargetNodes(ctx, clientset, selection)
	if err != nil {
		return true, err
	}
	if preResolved.Empty() {
		return true, fmt.Errorf("nodespawn: no scheduled target pods")
	}
	multiNode := len(preResolved.NodeNames) > 1

	metricsPassThrough := enableMetrics && !multiNode
	if enableMetrics && multiNode {
		logger.Warn("--metrics ignored: spawn covers multiple nodes; auto-port-forward only single-node spawns. Pass --local for workstation metrics.")
	}

	build := newChildArgsBuilder(cmd, metricsPassThrough)
	streams := genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr}

	var onRunning func(context.Context, *corev1.Pod) error
	if metricsPassThrough {
		onRunning = func(podCtx context.Context, pod *corev1.Pod) error {
			go func() {
				logger.Info("Forwarding metrics port",
					zap.String("local", fmt.Sprintf("127.0.0.1:%d", config.DefaultMetricsPort)),
					zap.String("pod", pod.Namespace+"/"+pod.Name))
				if err := nodespawn.StartPortForward(podCtx, restCfg, clientset, pod,
					config.DefaultMetricsPort, config.DefaultMetricsPort,
					io.Discard, io.Discard); err != nil && podCtx.Err() == nil {
					logger.Warn("Metrics port-forward exited", zap.Error(err))
				}
			}()
			return nil
		}
	}

	dynamic := dynamicSpawn
	if dynamic && diagnoseDuration != "" {
		logger.Warn("--dynamic-spawn ignored: incompatible with --diagnose (child pods would each restart the timer). Drop --diagnose or --dynamic-spawn.")
		dynamic = false
	}

	sa := spawnServiceAccount
	if sa == "" {
		sa = os.Getenv("PODTRACE_SPAWN_SA")
	}

	err = nodespawn.Run(ctx, nodespawn.RunOptions{
		Clientset:             clientset,
		RestConfig:            restCfg,
		Selection:             selection,
		Image:                 image,
		SpawnNamespace:        ns,
		BuildChildArgs:        build,
		OwnerHost:             host,
		OwnerPID:              os.Getpid(),
		Streams:               streams,
		OnPodRunning:          onRunning,
		DynamicReSpawn:        dynamic,
		ServiceAccountName:    sa,
		KeepSpawnPodOnFailure: keepSpawnPodOnFailure,
	})
	if err != nil {
		var exitErr *nodespawn.ExitError
		if errorsAs(err, &exitErr) {
			return true, exitErr
		}
		return true, err
	}
	return true, nil
}

// clusterHandles pulls the kube clientset and rest.Config from the resolver.
// Returns ok=false when the resolver doesn't expose them (mock paths).
func clusterHandles(resolver pkgkube.PodResolverInterface) (kubernetes.Interface, *rest.Config, bool) {
	cp, ok := resolver.(pkgkube.ClientsetProvider)
	if !ok {
		return nil, nil, false
	}
	rp, ok := resolver.(pkgkube.RestConfigProvider)
	if !ok {
		return nil, nil, false
	}
	return cp.GetClientset(), rp.GetRestConfig(), true
}

// selectionIsSpawnable is a guardrail: when the user invoked --version, --help,
// or one of the subcommands, we shouldn't try to spawn anything. The cobra
// layer keeps subcommands out of runPodtrace already, but we still need to
// bail on empty selection.
func selectionIsSpawnable(sel pkgkube.TargetSelection) bool {
	if len(sel.Pods) > 0 || sel.PodSelector != "" || sel.AllInNamespace {
		return true
	}
	return false
}

// newChildArgsBuilder returns a callback that reconstructs the argv for one
// spawned pod, walking the cobra flag set and emitting only flags the user
// actually changed (minus spawn-control flags) plus a fresh --pods list for
// the targets on this node.
func newChildArgsBuilder(cmd *cobra.Command, passMetrics bool) func(string, []nodespawn.PodRef) []string {
	return func(_ string, pods []nodespawn.PodRef) []string {
		args := []string{}
		cmd.Flags().Visit(func(f *pflag.Flag) {
			if _, drop := spawnControlFlags[f.Name]; drop {
				return
			}
			if f.Name == "metrics" && !passMetrics {
				return
			}
			args = append(args, "--"+f.Name+"="+f.Value.String())
		})
		for _, p := range pods {
			if p.ContainerID != "" {
				args = append(args, "--preresolved-pod="+p.PreResolved())
			}
		}
		return args
	}
}

// errorsAs is a minimal local helper to avoid importing "errors" twice in
// callsites that already import other things named errors.
func errorsAs(err error, target any) bool {
	type wrapped interface{ Unwrap() error }
	for err != nil {
		if t, ok := target.(**nodespawn.ExitError); ok {
			if e, ok := err.(*nodespawn.ExitError); ok {
				*t = e
				return true
			}
		}
		w, ok := err.(wrapped)
		if !ok {
			return false
		}
		err = w.Unwrap()
	}
	return false
}

var _ = fmt.Sprintf
