package kubernetes

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/validation"
	"go.uber.org/zap"
)

type TargetSelection struct {
	DefaultNamespace string
	Namespaces       []string
	PodSelector      string
	AllInNamespace   bool
	Pods             []string // supports "pod" or "namespace/pod"
	ContainerName    string
}

func (s TargetSelection) EffectiveNamespaces() []string {
	if len(s.Namespaces) > 0 {
		return uniqNonEmpty(s.Namespaces)
	}
	if s.DefaultNamespace != "" {
		return []string{s.DefaultNamespace}
	}
	return nil
}

func (s TargetSelection) PodRefSet() map[string]map[string]struct{} {
	refs := make(map[string]map[string]struct{})
	for _, p := range s.Pods {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ns := s.DefaultNamespace
		name := p
		if strings.Contains(p, "/") {
			parts := strings.SplitN(p, "/", 2)
			ns = parts[0]
			name = parts[1]
		}
		if refs[ns] == nil {
			refs[ns] = make(map[string]struct{})
		}
		refs[ns][name] = struct{}{}
	}
	return refs
}

type TargetRegistry struct {
	clientset   kubernetes.Interface
	selection   TargetSelection
	maxTargets  int
	podInf      cache.SharedIndexInformer
	factory     informers.SharedInformerFactory
	updates     chan []*PodInfo
	podNameRefs map[string]map[string]struct{}

	mu      sync.RWMutex
	targets map[types.UID]*PodInfo
}

func NewTargetRegistry(clientset kubernetes.Interface, selection TargetSelection) *TargetRegistry {
	return &TargetRegistry{
		clientset:   clientset,
		selection:   selection,
		maxTargets:  getIntEnv("PODTRACE_MAX_TARGET_PODS", 256),
		updates:     make(chan []*PodInfo, 8),
		targets:     make(map[types.UID]*PodInfo),
		podNameRefs: selection.PodRefSet(),
	}
}

func (tr *TargetRegistry) Start(ctx context.Context) error {
	if tr == nil || tr.clientset == nil {
		return fmt.Errorf("target registry requires a kubernetes clientset")
	}

	nsOpts := tr.selection.EffectiveNamespaces()
	namespace := metav1.NamespaceAll
	if len(nsOpts) == 1 {
		namespace = nsOpts[0]
	}

	var tweak func(*metav1.ListOptions)
	if tr.selection.PodSelector != "" {
		selector := tr.selection.PodSelector
		tweak = func(o *metav1.ListOptions) {
			o.LabelSelector = selector
		}
	}

	var factory informers.SharedInformerFactory
	if tweak != nil {
		factory = informers.NewSharedInformerFactoryWithOptions(tr.clientset, 0, informers.WithNamespace(namespace), informers.WithTweakListOptions(tweak))
	} else {
		factory = informers.NewSharedInformerFactoryWithOptions(tr.clientset, 0, informers.WithNamespace(namespace))
	}
	podInf := factory.Core().V1().Pods().Informer()
	_, _ = podInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			tr.handlePodUpsert(obj)
		},
		UpdateFunc: func(_, newObj interface{}) {
			tr.handlePodUpsert(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			tr.handlePodDelete(obj)
		},
	})

	tr.factory = factory
	tr.podInf = podInf
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), podInf.HasSynced) {
		return fmt.Errorf("timed out waiting for pod target registry cache sync")
	}

	tr.rebuildFromStore()
	tr.emitSnapshot()
	return nil
}

func (tr *TargetRegistry) Updates() <-chan []*PodInfo { return tr.updates }

func (tr *TargetRegistry) Snapshot() []*PodInfo {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	return clonePodInfos(tr.targets)
}

func (tr *TargetRegistry) rebuildFromStore() {
	if tr.podInf == nil {
		return
	}
	items := tr.podInf.GetStore().List()
	for _, obj := range items {
		tr.handlePodUpsert(obj)
	}
}

func (tr *TargetRegistry) handlePodUpsert(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok || pod == nil {
		return
	}
	if !tr.matchesSelection(pod) {
		tr.mu.Lock()
		delete(tr.targets, pod.UID)
		tr.mu.Unlock()
		tr.emitSnapshot()
		return
	}

	info, err := resolvePodInfoFromObject(context.Background(), pod, tr.selection.ContainerName)
	if err != nil {
		return
	}

	tr.mu.Lock()
	if len(tr.targets) >= tr.maxTargets {
		if _, exists := tr.targets[pod.UID]; !exists {
			tr.mu.Unlock()
			logger.Warn("Target registry reached max target limit", zap.Int("max_targets", tr.maxTargets))
			return
		}
	}
	tr.targets[pod.UID] = info
	tr.mu.Unlock()
	tr.emitSnapshot()
}

func (tr *TargetRegistry) handlePodDelete(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		pod, ok = tombstone.Obj.(*corev1.Pod)
		if !ok || pod == nil {
			return
		}
	}
	tr.mu.Lock()
	delete(tr.targets, pod.UID)
	tr.mu.Unlock()
	tr.emitSnapshot()
}

func (tr *TargetRegistry) matchesSelection(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	if len(tr.selection.EffectiveNamespaces()) > 0 {
		matched := false
		for _, ns := range tr.selection.EffectiveNamespaces() {
			if pod.Namespace == ns {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(tr.podNameRefs) > 0 {
		nsSet, ok := tr.podNameRefs[pod.Namespace]
		if !ok {
			return false
		}
		if _, ok := nsSet[pod.Name]; !ok {
			return false
		}
	}
	return true
}

func (tr *TargetRegistry) emitSnapshot() {
	snap := tr.Snapshot()
	select {
	case tr.updates <- snap:
	default:
		// Keep latest snapshot without blocking.
		select {
		case <-tr.updates:
		default:
		}
		select {
		case tr.updates <- snap:
		default:
		}
	}
}

func resolvePodInfoFromObject(ctx context.Context, pod *corev1.Pod, containerName string) (*PodInfo, error) {
	if pod == nil {
		return nil, fmt.Errorf("nil pod")
	}
	if len(pod.Status.ContainerStatuses) == 0 {
		return nil, fmt.Errorf("pod %s/%s has no container statuses", pod.Namespace, pod.Name)
	}

	var containerStatus *corev1.ContainerStatus
	var containerSpec *corev1.Container
	if containerName != "" {
		for i, status := range pod.Status.ContainerStatuses {
			if status.Name == containerName {
				containerStatus = &pod.Status.ContainerStatuses[i]
				for j, spec := range pod.Spec.Containers {
					if spec.Name == containerName {
						containerSpec = &pod.Spec.Containers[j]
						break
					}
				}
				break
			}
		}
		if containerStatus == nil {
			return nil, fmt.Errorf("container %s not found in pod %s/%s", containerName, pod.Namespace, pod.Name)
		}
	} else {
		containerStatus = &pod.Status.ContainerStatuses[0]
		containerSpec = &pod.Spec.Containers[0]
	}

	containerID := containerStatus.ContainerID
	parts := strings.Split(containerID, "://")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid container id format for %s/%s: %q", pod.Namespace, pod.Name, containerID)
	}
	shortID := parts[1]
	if !validation.ValidateContainerID(shortID) {
		return nil, fmt.Errorf("container id validation failed for %s/%s", pod.Namespace, pod.Name)
	}

	resolveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cgroupPath, err := resolveCgroupPathCRI(resolveCtx, shortID)
	if err != nil || cgroupPath == "" {
		cgroupPath, err = findCgroupPath(shortID)
		if err != nil || cgroupPath == "" {
			cgroupPath, err = findCgroupPathFromProc(shortID)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve cgroup path for %s/%s: %w", pod.Namespace, pod.Name, err)
			}
		}
	}

	labels := make(map[string]string, len(pod.Labels))
	for k, v := range pod.Labels {
		labels[k] = v
	}
	var ownerKind, ownerName string
	if len(pod.OwnerReferences) > 0 {
		ownerKind = pod.OwnerReferences[0].Kind
		ownerName = pod.OwnerReferences[0].Name
	}

	name := ""
	if containerSpec != nil {
		name = containerSpec.Name
	}
	return &PodInfo{
		PodName:       pod.Name,
		Namespace:     pod.Namespace,
		ContainerID:   shortID,
		CgroupPath:    cgroupPath,
		ContainerName: name,
		Labels:        labels,
		PodIP:         pod.Status.PodIP,
		OwnerKind:     ownerKind,
		OwnerName:     ownerName,
	}, nil
}

func clonePodInfos(in map[types.UID]*PodInfo) []*PodInfo {
	out := make([]*PodInfo, 0, len(in))
	for _, p := range in {
		cp := *p
		out = append(out, &cp)
	}
	return out
}

func uniqNonEmpty(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func getIntEnv(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
