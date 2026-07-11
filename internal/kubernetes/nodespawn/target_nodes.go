package nodespawn

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	pkgkube "github.com/podtrace/podtrace/internal/kubernetes"
	"github.com/podtrace/podtrace/internal/logger"
	"go.uber.org/zap"
)

// PodRef holds everything the workstation pre-resolves about a target pod so
// the spawned binary can build its PodInfo without a single K8s API call.
type PodRef struct {
	Namespace     string
	Name          string
	ContainerID   string
	ContainerName string
}

// String returns the "namespace/name" form ResolvePod accepts.
func (r PodRef) String() string {
	return r.Namespace + "/" + r.Name
}

// PreResolved returns the "ns/name/containerID/containerName" form the spawn
// pod accepts via --preresolved-pod (single string keeps the argv compact).
func (r PodRef) PreResolved() string {
	return r.Namespace + "/" + r.Name + "/" + r.ContainerID + "/" + r.ContainerName
}

// NodeTargets groups the resolved target pods by the node they run on.
// One ephemeral pod will be spawned per key.
type NodeTargets struct {
	ByNode            map[string][]PodRef
	NodeNames         []string
	TolerationsByNode map[string][]corev1.Toleration
}

// Empty reports whether ResolveTargetNodes returned no pods at all.
func (t NodeTargets) Empty() bool { return len(t.NodeNames) == 0 }

// ResolveTargetNodes walks the TargetSelection, lists pods that match, and
// groups them by node.
func ResolveTargetNodes(ctx context.Context, clientset kubernetes.Interface, sel pkgkube.TargetSelection) (NodeTargets, error) {
	if clientset == nil {
		return NodeTargets{}, fmt.Errorf("nodespawn: clientset is nil")
	}

	byNode := map[string][]PodRef{}
	tolByNode := map[string][]corev1.Toleration{}
	tolSeen := map[string]map[string]struct{}{}
	unscheduled := []PodRef{}
	missingContainer := []PodRef{}
	routedWithoutID := []PodRef{}
	seen := map[string]struct{}{}

	add := func(pod *corev1.Pod) {
		ref := PodRef{Namespace: pod.Namespace, Name: pod.Name}
		if _, dup := seen[ref.String()]; dup {
			return
		}
		seen[ref.String()] = struct{}{}
		if pod.Spec.NodeName == "" {
			unscheduled = append(unscheduled, ref)
			return
		}
		cs := pickRunningContainer(pod, sel.ContainerName)
		if sel.ContainerName != "" && cs == nil {
			missingContainer = append(missingContainer, ref)
			return
		}
		if cs != nil {
			ref.ContainerName = cs.Name
			if idx := indexAfterScheme(cs.ContainerID); idx >= 0 {
				ref.ContainerID = cs.ContainerID[idx:]
			}
		} else {
			routedWithoutID = append(routedWithoutID, ref)
		}
		node := pod.Spec.NodeName
		byNode[node] = append(byNode[node], ref)
		if tolSeen[node] == nil {
			tolSeen[node] = map[string]struct{}{}
		}
		for _, t := range pod.Spec.Tolerations {
			k := tolerationKey(t)
			if _, dup := tolSeen[node][k]; dup {
				continue
			}
			tolSeen[node][k] = struct{}{}
			tolByNode[node] = append(tolByNode[node], t)
		}
	}

	for ns, names := range sel.PodRefSet() {
		for name := range names {
			pod, err := clientset.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return NodeTargets{}, fmt.Errorf("nodespawn: get pod %s/%s: %w", ns, name, err)
			}
			add(pod)
		}
	}

	if sel.PodSelector != "" || sel.AllInNamespace || len(sel.Namespaces) > 1 {
		listOpts := metav1.ListOptions{LabelSelector: sel.PodSelector}
		for _, ns := range sel.EffectiveNamespaces() {
			list, err := clientset.CoreV1().Pods(ns).List(ctx, listOpts)
			if err != nil {
				return NodeTargets{}, fmt.Errorf("nodespawn: list pods in %s: %w", ns, err)
			}
			for i := range list.Items {
				pod := &list.Items[i]
				if pod.DeletionTimestamp != nil {
					continue
				}
				add(pod)
			}
		}
	}

	if len(missingContainer) > 0 && len(byNode) == 0 {
		return NodeTargets{}, fmt.Errorf("nodespawn: no matched pod has a running container named %q: %s",
			sel.ContainerName, joinRefs(missingContainer))
	}
	if len(unscheduled) > 0 && len(byNode) == 0 {
		return NodeTargets{}, fmt.Errorf("nodespawn: %d target pod(s) are not yet scheduled to a node: %s",
			len(unscheduled), joinRefs(unscheduled))
	}
	if len(missingContainer) > 0 {
		logger.Warn("Skipping target pod(s) with no running container matching the requested name",
			zap.String("container", sel.ContainerName),
			zap.Int("skipped", len(missingContainer)),
			zap.String("pods", joinRefs(missingContainer)))
	}
	if len(unscheduled) > 0 {
		logger.Warn("Skipping unscheduled target pod(s)",
			zap.Int("skipped", len(unscheduled)),
			zap.String("pods", joinRefs(unscheduled)))
	}
	if len(routedWithoutID) > 0 {
		logger.Warn("Target pod(s) have no running container yet; routed without a resolved container ID",
			zap.Int("count", len(routedWithoutID)),
			zap.String("pods", joinRefs(routedWithoutID)))
	}

	out := NodeTargets{ByNode: byNode, TolerationsByNode: tolByNode}
	for n := range byNode {
		out.NodeNames = append(out.NodeNames, n)
	}
	sort.Strings(out.NodeNames)
	for n := range byNode {
		sort.Slice(byNode[n], func(i, j int) bool {
			a, b := byNode[n][i], byNode[n][j]
			if a.Namespace != b.Namespace {
				return a.Namespace < b.Namespace
			}
			return a.Name < b.Name
		})
	}
	return out, nil
}

// pickRunningContainer returns the running container matching name, or the
// first running container when name is empty.
func pickRunningContainer(pod *corev1.Pod, name string) *corev1.ContainerStatus {
	if pod == nil {
		return nil
	}
	for i := range pod.Status.ContainerStatuses {
		cs := &pod.Status.ContainerStatuses[i]
		if cs.State.Running == nil || cs.ContainerID == "" {
			continue
		}
		if name != "" && cs.Name != name {
			continue
		}
		return cs
	}
	return nil
}

// indexAfterScheme returns the offset right after "://" in a containerID like
// "containerd://abc123" so the caller can slice off the runtime prefix.
func indexAfterScheme(s string) int {
	i := strings.Index(s, "://")
	if i < 0 {
		return -1
	}
	return i + 3
}

// tolerationKey is a stable string used to dedupe Tolerations across the
// target pods on one node.
func tolerationKey(t corev1.Toleration) string {
	sec := "nil"
	if t.TolerationSeconds != nil {
		sec = fmt.Sprintf("%d", *t.TolerationSeconds)
	}
	return string(t.Effect) + "|" + t.Key + "|" + string(t.Operator) + "|" + t.Value + "|" + sec
}

func joinRefs(refs []PodRef) string {
	s := make([]string, len(refs))
	for i, r := range refs {
		s[i] = r.String()
	}
	return strings.Join(s, ", ")
}
