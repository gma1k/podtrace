package kubernetes

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/podworkload"
	"go.uber.org/zap"
)

type TargetSelection struct {
	DefaultNamespace string
	Namespaces       []string
	PodSelector      string
	AllInNamespace   bool
	Pods             []string // supports "pod" or "namespace/pod"
	ContainerName    string
	NodeName         string
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

// WatchNamespaces is where target pods can live: the namespaces the pod
// refs name when there are any, since each ref carries its own namespace,
// otherwise the selection's namespaces, and every namespace when it names
// none.
func (s TargetSelection) WatchNamespaces() []string {
	if refs := s.PodRefSet(); len(refs) > 0 {
		out := make([]string, 0, len(refs))
		for ns := range refs {
			out = append(out, ns)
		}
		sort.Strings(out)
		return out
	}
	if ns := s.EffectiveNamespaces(); len(ns) > 0 {
		return ns
	}
	return []string{metav1.NamespaceAll}
}

// Matcher returns the predicate both the spawn and the local plane apply to a
// candidate pod, so the two select the same pods: a pod named by a pod ref
// when there are refs, otherwise one in the selection's namespaces, and in
// either case one the label selector matches, and, when the selection names a
// node, one scheduled on it.
func (s TargetSelection) Matcher() (func(*corev1.Pod) bool, error) {
	selector := labels.Everything()
	if s.PodSelector != "" {
		parsed, err := labels.Parse(s.PodSelector)
		if err != nil {
			return nil, fmt.Errorf("invalid pod selector %q: %w", s.PodSelector, err)
		}
		selector = parsed
	}
	refs := s.PodRefSet()
	namespaces := map[string]struct{}{}
	for _, ns := range s.EffectiveNamespaces() {
		namespaces[ns] = struct{}{}
	}
	return func(pod *corev1.Pod) bool {
		if pod == nil {
			return false
		}
		if s.NodeName != "" && pod.Spec.NodeName != s.NodeName {
			return false
		}
		if len(refs) > 0 {
			if _, ok := refs[pod.Namespace][pod.Name]; !ok {
				return false
			}
		} else if len(namespaces) > 0 {
			if _, ok := namespaces[pod.Namespace]; !ok {
				return false
			}
		}
		return selector.Matches(labels.Set(pod.Labels))
	}, nil
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
	clientset  kubernetes.Interface
	selection  TargetSelection
	maxTargets int
	podInfs    []cache.SharedIndexInformer
	factories  []informers.SharedInformerFactory
	updates    chan []*PodInfo
	matches    func(*corev1.Pod) bool
	matcherErr error

	mu      sync.RWMutex
	targets map[types.UID]*PodInfo
	deleted map[types.UID]time.Time

	capped map[types.UID]string

	pendingMu sync.Mutex
	pending   map[types.UID]*corev1.Pod
	pendingCh chan struct{}

	workerDone chan struct{}
}

func NewTargetRegistry(clientset kubernetes.Interface, selection TargetSelection) *TargetRegistry {
	matches, err := selection.Matcher()
	return &TargetRegistry{
		clientset:  clientset,
		selection:  selection,
		maxTargets: getIntEnv("PODTRACE_MAX_TARGET_PODS", 256),
		updates:    make(chan []*PodInfo, 8),
		targets:    make(map[types.UID]*PodInfo),
		deleted:    make(map[types.UID]time.Time),
		capped:     make(map[types.UID]string),
		matches:    matches,
		matcherErr: err,
		pending:    make(map[types.UID]*corev1.Pod),
		pendingCh:  make(chan struct{}, 1),
		workerDone: make(chan struct{}),
	}
}

// Done is closed once the resolution worker of a successfully started
// registry has returned after the context given to Start ended, so a caller
// can wait for it to stop touching the node's cgroup and /proc views.
func (tr *TargetRegistry) Done() <-chan struct{} {
	return tr.workerDone
}

const cacheSyncTimeout = 30 * time.Second

// deletedPodMemory is how long a deleted pod's UID keeps a late upsert from
// re-adding it.
const deletedPodMemory = 10 * time.Minute

func (tr *TargetRegistry) Start(ctx context.Context) error {
	if tr == nil || tr.clientset == nil {
		return fmt.Errorf("target registry requires a kubernetes clientset")
	}

	if tr.matcherErr != nil {
		return tr.matcherErr
	}
	watchNamespaces := tr.selection.WatchNamespaces()

	tweak := targetListOptions(tr.selection)

	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { tr.enqueueUpsert(obj) },
		UpdateFunc: func(_, newObj interface{}) { tr.enqueueUpsert(newObj) },
		DeleteFunc: func(obj interface{}) { tr.handlePodDelete(obj) },
	}

	var syncFns []cache.InformerSynced
	for _, ns := range watchNamespaces {
		opts := []informers.SharedInformerOption{informers.WithNamespace(ns)}
		opts = append(opts, informers.WithTweakListOptions(tweak))
		factory := informers.NewSharedInformerFactoryWithOptions(tr.clientset, 0, opts...)
		podInf := factory.Core().V1().Pods().Informer()
		if _, err := podInf.AddEventHandler(handlers); err != nil {
			return fmt.Errorf("add pod event handler for namespace %q: %w", ns, err)
		}
		tr.factories = append(tr.factories, factory)
		tr.podInfs = append(tr.podInfs, podInf)
		syncFns = append(syncFns, podInf.HasSynced)
		factory.Start(ctx.Done())
	}
	syncCtx, cancel := context.WithTimeout(ctx, cacheSyncTimeout)
	defer cancel()
	if !cache.WaitForCacheSync(syncCtx.Done(), syncFns...) {
		return fmt.Errorf("timed out waiting for pod target registry cache sync "+
			"(after %s; check pods list/watch RBAC)", cacheSyncTimeout)
	}

	tr.rebuildFromStore(ctx)
	tr.emitSnapshot()
	go tr.resolveWorker(ctx)
	return nil
}

// targetListOptions narrows the pod LIST/WATCH to the label selector and, for
// a per-node tracer, to its node, so the API server never streams pods the
// tracer could not attach to.
func targetListOptions(selection TargetSelection) func(*metav1.ListOptions) {
	labelSelector := selection.PodSelector
	var fieldSelector string
	if selection.NodeName != "" {
		fieldSelector = fields.OneTermEqualSelector("spec.nodeName", selection.NodeName).String()
	}
	return func(o *metav1.ListOptions) {
		o.LabelSelector = labelSelector
		o.FieldSelector = fieldSelector
	}
}

// enqueueUpsert records the pod for the resolution worker. It runs on the
// informer's delivery goroutine, so it must not block or perform I/O.
func (tr *TargetRegistry) enqueueUpsert(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok || pod == nil {
		return
	}
	tr.pendingMu.Lock()
	tr.pending[pod.UID] = pod
	tr.pendingMu.Unlock()
	select {
	case tr.pendingCh <- struct{}{}:
	default:
	}
}

// resolveWorker drains pending pods and resolves them off the informer
// goroutine.
func (tr *TargetRegistry) resolveWorker(ctx context.Context) {
	defer close(tr.workerDone)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tr.pendingCh:
		}
		for {
			tr.pendingMu.Lock()
			var pod *corev1.Pod
			var uid types.UID
			for u, p := range tr.pending {
				uid, pod = u, p
				break
			}
			if pod != nil {
				delete(tr.pending, uid)
			}
			tr.pendingMu.Unlock()
			if pod == nil {
				break
			}
			tr.handlePodUpsert(ctx, pod)
		}
	}
}

func (tr *TargetRegistry) Updates() <-chan []*PodInfo { return tr.updates }

func (tr *TargetRegistry) Snapshot() []*PodInfo {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	return clonePodInfos(tr.targets)
}

// rebuildFromStore loads every cached pod without publishing: a snapshot
// emitted after the first of several pods would tell the tracer the others
// are gone, and it would detach them until the next snapshot. The caller
// publishes once, when the set is complete.
func (tr *TargetRegistry) rebuildFromStore(ctx context.Context) {
	for _, inf := range tr.podInfs {
		for _, obj := range inf.GetStore().List() {
			if pod, ok := obj.(*corev1.Pod); ok && pod != nil {
				tr.upsertPod(ctx, pod)
			}
		}
	}
}

func (tr *TargetRegistry) handlePodUpsert(ctx context.Context, pod *corev1.Pod) {
	if tr.upsertPod(ctx, pod) {
		tr.emitSnapshot()
	}
}

// upsertPod applies one pod to the target set and reports whether the set
// changed in a way that must be published.
func (tr *TargetRegistry) upsertPod(ctx context.Context, pod *corev1.Pod) bool {
	if !tr.matchesSelection(pod) {
		tr.mu.Lock()
		_, wasTarget := tr.targets[pod.UID]
		delete(tr.targets, pod.UID)
		delete(tr.capped, pod.UID)
		tr.mu.Unlock()
		if wasTarget {
			tr.requeueCapped()
		}
		return wasTarget
	}

	tr.mu.Lock()
	if _, gone := tr.deleted[pod.UID]; gone {
		tr.mu.Unlock()
		return false
	}
	current := tr.targets[pod.UID]
	if current == nil && tr.atCapLocked(pod) {
		tr.mu.Unlock()
		return false
	}
	tr.mu.Unlock()

	if current != nil {
		if refreshed, ok := refreshResolvedTarget(current, pod, tr.selection.ContainerName); ok {
			return tr.storeTarget(pod, refreshed)
		}
	}

	info, err := resolvePodInfoFromObject(ctx, pod, tr.selection.ContainerName)
	if err != nil {
		logger.Debug("Target pod resolution failed",
			zap.String("namespace", pod.Namespace),
			zap.String("pod", pod.Name),
			zap.Error(err))
		tr.mu.Lock()
		stale := tr.targets[pod.UID]
		dropped := false
		if stale != nil && !podHasContainerID(pod, stale.ContainerID) {
			delete(tr.targets, pod.UID)
			dropped = true
		}
		tr.mu.Unlock()
		if dropped {
			logger.Debug("Dropped stale target after container restart",
				zap.String("namespace", pod.Namespace),
				zap.String("pod", pod.Name),
				zap.String("stale_container_id", stale.ContainerID))
			tr.requeueCapped()
		}
		return dropped
	}
	return tr.storeTarget(pod, info)
}

// storeTarget records info for pod unless the pod was deleted or the cap
// filled while it resolved, and reports whether the published set changed:
// a resolution that yields the target already held does not republish, so
// the tracer does not re-attach.
func (tr *TargetRegistry) storeTarget(pod *corev1.Pod, info *PodInfo) bool {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if _, gone := tr.deleted[pod.UID]; gone {
		return false
	}
	existing, exists := tr.targets[pod.UID]
	if !exists && tr.atCapLocked(pod) {
		return false
	}
	delete(tr.capped, pod.UID)
	tr.targets[pod.UID] = info
	return !exists || !podInfoEqual(existing, info)
}

// atCapLocked reports whether the target set is full, remembering pod so it
// is retried when a slot frees. tr.mu must be held.
func (tr *TargetRegistry) atCapLocked(pod *corev1.Pod) bool {
	if len(tr.targets) < tr.maxTargets {
		return false
	}
	if _, known := tr.capped[pod.UID]; !known {
		logger.Warn("Target registry reached max target limit; pod waits for a free slot",
			zap.Int("max_targets", tr.maxTargets),
			zap.String("namespace", pod.Namespace),
			zap.String("pod", pod.Name))
	}
	tr.capped[pod.UID] = pod.Namespace + "/" + pod.Name
	return true
}

// requeueCapped hands every pod turned away at the cap back to the
// resolution worker, using its current informer copy, after a target left
// the set. Pods no longer in any informer store are forgotten.
func (tr *TargetRegistry) requeueCapped() {
	tr.mu.Lock()
	keys := make(map[types.UID]string, len(tr.capped))
	for uid, key := range tr.capped {
		keys[uid] = key
	}
	tr.mu.Unlock()
	for uid, key := range keys {
		pod := tr.cachedPod(key)
		if pod == nil || pod.UID != uid {
			tr.mu.Lock()
			delete(tr.capped, uid)
			tr.mu.Unlock()
		}
		if pod != nil {
			tr.enqueueUpsert(pod)
		}
	}
}

func (tr *TargetRegistry) cachedPod(key string) *corev1.Pod {
	for _, inf := range tr.podInfs {
		obj, exists, err := inf.GetStore().GetByKey(key)
		if err != nil || !exists {
			continue
		}
		if pod, ok := obj.(*corev1.Pod); ok && pod != nil {
			return pod
		}
	}
	return nil
}

// refreshResolvedTarget reuses current's resolved containers when the pod
// still runs exactly those containers and every one has a cgroup, so a
// status update that changed nothing the tracer attaches to (a readiness
// flip, a label edit) skips the /proc, cgroup and CRI work.
func refreshResolvedTarget(current *PodInfo, pod *corev1.Pod, containerName string) (*PodInfo, bool) {
	statuses := pickContainers(pod, containerName)
	if len(statuses) == 0 || len(statuses) != len(current.Containers) {
		return nil, false
	}
	running := make(map[string]string, len(statuses))
	for _, cs := range statuses {
		id, err := shortContainerID(cs.ContainerID)
		if err != nil {
			return nil, false
		}
		running[id] = cs.Name
	}
	for _, c := range current.Containers {
		if c.CgroupPath == "" {
			return nil, false
		}
		if name, ok := running[c.ID]; !ok || name != c.Name {
			return nil, false
		}
	}
	refreshed := *current
	refreshed.Containers = append([]ContainerTarget(nil), current.Containers...)
	refreshed.Labels = copyLabels(pod.Labels)
	refreshed.PodIP = pod.Status.PodIP
	refreshed.OwnerKind, refreshed.OwnerName = podworkload.Of(pod)
	return &refreshed, true
}

func podInfoEqual(a, b *PodInfo) bool {
	if a.PodName != b.PodName || a.Namespace != b.Namespace ||
		a.ContainerID != b.ContainerID || a.CgroupPath != b.CgroupPath ||
		a.ContainerName != b.ContainerName || a.PodIP != b.PodIP ||
		a.OwnerKind != b.OwnerKind || a.OwnerName != b.OwnerName ||
		len(a.Containers) != len(b.Containers) || len(a.Labels) != len(b.Labels) {
		return false
	}
	for i := range a.Containers {
		if a.Containers[i] != b.Containers[i] {
			return false
		}
	}
	for k, v := range a.Labels {
		if other, ok := b.Labels[k]; !ok || other != v {
			return false
		}
	}
	return true
}

func copyLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// podHasContainerID reports whether any of the pod's current container
// statuses carries the given (runtime-prefix-stripped) container ID.
func podHasContainerID(pod *corev1.Pod, shortID string) bool {
	if shortID == "" {
		return false
	}
	for _, cs := range pod.Status.ContainerStatuses {
		id := cs.ContainerID
		if i := strings.Index(id, "://"); i >= 0 {
			id = id[i+3:]
		}
		if id == shortID {
			return true
		}
	}
	return false
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
	tr.pendingMu.Lock()
	delete(tr.pending, pod.UID)
	tr.pendingMu.Unlock()
	now := time.Now()
	tr.mu.Lock()
	_, wasTarget := tr.targets[pod.UID]
	delete(tr.targets, pod.UID)
	delete(tr.capped, pod.UID)
	for uid, at := range tr.deleted {
		if now.Sub(at) > deletedPodMemory {
			delete(tr.deleted, uid)
		}
	}
	tr.deleted[pod.UID] = now
	tr.mu.Unlock()
	tr.emitSnapshot()
	if wasTarget {
		tr.requeueCapped()
	}
}

func (tr *TargetRegistry) matchesSelection(pod *corev1.Pod) bool {
	return tr.matches != nil && tr.matches(pod)
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

	statuses := pickContainers(pod, containerName)
	if len(statuses) == 0 {
		return nil, fmt.Errorf("no running container matching %q in pod %s/%s", containerName, pod.Namespace, pod.Name)
	}

	resolveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	targets := resolveContainerTargets(resolveCtx, pod, statuses)
	if len(targets) == 0 {
		for _, cs := range statuses {
			shortID, err := shortContainerID(cs.ContainerID)
			if err != nil {
				continue
			}
			targets = append(targets, ContainerTarget{Name: cs.Name, ID: shortID})
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("no usable container in pod %s/%s", pod.Namespace, pod.Name)
		}
		logger.Debug("No container cgroup resolved; keeping target with container IDs only",
			zap.String("pod", pod.Namespace+"/"+pod.Name))
	}

	ownerKind, ownerName := podworkload.Of(pod)

	return &PodInfo{
		PodName:       pod.Name,
		Namespace:     pod.Namespace,
		Containers:    targets,
		ContainerID:   targets[0].ID,
		CgroupPath:    targets[0].CgroupPath,
		ContainerName: targets[0].Name,
		Labels:        copyLabels(pod.Labels),
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
