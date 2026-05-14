package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/operator"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// AgentReconciler is the single controller the agent runs.
type AgentReconciler struct {
	client.Client
	NodeName        string
	SystemNamespace string
	Router          *Router
	Metrics         *Metrics

	TargetsCh chan tracer.TargetSet

	ExporterBuilder func(payload *BundlePayload, crKey CRKey) (tracer.Exporter, error)

	CgroupResolver func(pods []*corev1.Pod) (map[uint64]struct{}, error)

	exporterCacheMu sync.Mutex
	exporterCache   map[CRKey]cachedExporter
}

type cachedExporter struct {
	bundleRV string
	exporter tracer.Exporter
}

// SetupWithManager registers the reconciler onto the manager with all
// three watched sources.
func (r *AgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.ExporterBuilder == nil {
		r.ExporterBuilder = BuildExporter
	}
	if r.CgroupResolver == nil {
		r.CgroupResolver = resolveCgroupIDs
	}
	r.exporterCache = map[CRKey]cachedExporter{}

	return ctrl.NewControllerManagedBy(mgr).
		Named("agent").
		For(&podtracev1alpha1.PodTrace{}).
		Watches(&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueAllPodTraces),
			builder.WithPredicates(podChangePredicates()),
		).
		Watches(&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueOnBundleChange),
		).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// Reconcile rebuilds the full router rule set.
func (r *AgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrllog.FromContext(ctx).WithName("agent").WithValues("nudged_by", req.String())

	if r.Metrics != nil {
		r.Metrics.ReconcileTotal.Inc()
	}

	var ptList podtracev1alpha1.PodTraceList
	if err := r.List(ctx, &ptList); err != nil {
		return ctrl.Result{}, fmt.Errorf("list PodTrace: %w", err)
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods); err != nil {
		return ctrl.Result{}, fmt.Errorf("list Pods: %w", err)
	}
	localPods := make([]*corev1.Pod, 0, len(pods.Items))
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Spec.NodeName == r.NodeName {
			localPods = append(localPods, p)
		}
	}

	rules := make([]CRRule, 0, len(ptList.Items))
	activeKeys := make(map[CRKey]struct{}, len(ptList.Items))

	for i := range ptList.Items {
		pt := &ptList.Items[i]
		if pt.Spec.Paused {
			continue
		}
		key := CRKey{Namespace: pt.Namespace, Name: pt.Name}

		bundle, err := LoadBundle(ctx, r.Client, r.SystemNamespace, pt.UID)
		if err != nil {
			if apierrors.IsNotFound(err) {
				logger.V(1).Info("bundle not yet synced", "cr", key)
				continue
			}
			logger.Error(err, "load bundle", "cr", key)
			rules = append(rules, CRRule{
				Key:     key,
				Filters: filtersToSet(pt.Spec.Filters),
				Err:     fmt.Errorf("load bundle: %w", err),
			})
			activeKeys[key] = struct{}{}
			continue
		}

		matched, err := MatchPodTraceAgainstPods(pt, localPods, bundle.TargetNamespaces)
		if err != nil {
			logger.Error(err, "match pods", "cr", key)
			rules = append(rules, CRRule{
				Key: key,
				Err: fmt.Errorf("match pods: %w", err),
			})
			activeKeys[key] = struct{}{}
			continue
		}
		if len(matched) == 0 {
			r.releaseExporter(key)
			continue
		}

		cgroupIDs, err := r.CgroupResolver(matched)
		if err != nil {
			logger.Error(err, "resolve cgroup IDs", "cr", key)
			rules = append(rules, CRRule{
				Key:         key,
				Filters:     filtersToSet(pt.Spec.Filters),
				MatchedPods: lenToInt32(len(matched)),
				Err:         fmt.Errorf("resolve cgroup IDs: %w", err),
			})
			activeKeys[key] = struct{}{}
			continue
		}

		exporter, err := r.obtainExporter(key, bundle)
		if err != nil {
			logger.V(1).Info("build exporter (tombstoned on CR)", "cr", key, "error", err)
			rules = append(rules, CRRule{
				Key:            key,
				CgroupIDs:      cgroupIDs,
				Filters:        filtersToSet(pt.Spec.Filters),
				BundleRevision: bundle.ResourceVer,
				MatchedPods:    lenToInt32(len(matched)),
				Err:            fmt.Errorf("build exporter: %w", err),
			})
			activeKeys[key] = struct{}{}
			continue
		}

		rules = append(rules, CRRule{
			Key:            key,
			CgroupIDs:      cgroupIDs,
			Filters:        filtersToSet(pt.Spec.Filters),
			Exporter:       exporter,
			BundleRevision: bundle.ResourceVer,
			MatchedPods:    lenToInt32(len(matched)),
		})
		activeKeys[key] = struct{}{}
	}

	r.reapStaleExporters(activeKeys)

	r.Router.Publish(rules)

	targets := buildTargetSet(rules, localPods)
	select {
	case r.TargetsCh <- targets:
	default:
		select {
		case <-r.TargetsCh:
		default:
		}
		select {
		case r.TargetsCh <- targets:
		default:
		}
	}

	if r.Metrics != nil {
		r.Metrics.RefreshFromRouter(r.Router)
	}

	return ctrl.Result{}, nil
}

func (r *AgentReconciler) enqueueAllPodTraces(ctx context.Context, _ client.Object) []reconcile.Request {
	var list podtracev1alpha1.PodTraceList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, len(list.Items))
	for _, pt := range list.Items {
		out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: pt.Namespace,
			Name:      pt.Name,
		}})
	}
	return out
}

// enqueueOnBundleChange handles ConfigMap watches: only bundle
// ConfigMaps (with our managed-by label) produce reconcile requests,
// and each such event enqueues every PodTrace (the bundle label tells
// us which CR owns the bundle but the reconcile rebuilds all anyway).
func (r *AgentReconciler) enqueueOnBundleChange(ctx context.Context, obj client.Object) []reconcile.Request {
	if obj.GetLabels()[operator.LabelManagedBy] != operator.ManagedByValue {
		return nil
	}
	if obj.GetLabels()[operator.LabelComponent] != operator.ComponentBundle {
		return nil
	}
	return r.enqueueAllPodTraces(ctx, obj)
}

// obtainExporter returns the cached Exporter for this CR if the
// bundle ResourceVersion is unchanged, otherwise builds a new one and
// closes the stale entry.
func (r *AgentReconciler) obtainExporter(key CRKey, bundle *BundlePayload) (tracer.Exporter, error) {
	r.exporterCacheMu.Lock()
	defer r.exporterCacheMu.Unlock()

	if entry, ok := r.exporterCache[key]; ok {
		if entry.bundleRV == bundle.ResourceVer {
			return entry.exporter, nil
		}
		if entry.exporter != nil {
			_ = entry.exporter.Close(context.Background())
		}
	}
	exporter, err := r.ExporterBuilder(bundle, key)
	if err != nil {
		return nil, err
	}
	r.exporterCache[key] = cachedExporter{
		bundleRV: bundle.ResourceVer,
		exporter: exporter,
	}
	return exporter, nil
}

// releaseExporter closes and removes the cached exporter for key.
func (r *AgentReconciler) releaseExporter(key CRKey) {
	r.exporterCacheMu.Lock()
	entry, ok := r.exporterCache[key]
	delete(r.exporterCache, key)
	r.exporterCacheMu.Unlock()
	if ok && entry.exporter != nil {
		_ = entry.exporter.Close(context.Background())
	}
}

// reapStaleExporters closes exporters whose CR keys did not appear in
// the active set this reconcile. Prevents leak when a CR is deleted.
func (r *AgentReconciler) reapStaleExporters(active map[CRKey]struct{}) {
	r.exporterCacheMu.Lock()
	var stale []CRKey
	for k := range r.exporterCache {
		if _, ok := active[k]; !ok {
			stale = append(stale, k)
		}
	}
	r.exporterCacheMu.Unlock()
	for _, k := range stale {
		r.releaseExporter(k)
	}
}

// resolveCgroupIDs maps each matched pod's cgroup path to its inode
// number — the value the kernel stamps on every event.
func resolveCgroupIDs(pods []*corev1.Pod) (map[uint64]struct{}, error) {
	out := map[uint64]struct{}{}
	root := discoverKubepodsRoot()
	for _, p := range pods {
		path := cgroupPathForPod(p, root)
		if path == "" {
			continue
		}
		if id, err := cgroupIDFromPath(path); err == nil {
			out[id] = struct{}{}
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			child := filepath.Join(path, e.Name())
			if id, err := cgroupIDFromPath(child); err == nil {
				out[id] = struct{}{}
			}
		}
	}
	return out, nil
}

// kubepodsRootCandidates lists the well-known cgroup directories
// kubelet publishes per-pod slices under.
var kubepodsRootCandidates = []string{
	"/sys/fs/cgroup/kubepods.slice",
	"/sys/fs/cgroup/kubepods",
	"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice",
	"/sys/fs/cgroup/system.slice/kubelet.service/kubepods",
}

// discoverKubepodsRoot returns the first kubepods root that exists on
// this node.
func discoverKubepodsRoot() string {
	for _, c := range kubepodsRootCandidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// cgroupPathForPod composes the per-pod cgroup directory under a
// discovered root.
func cgroupPathForPod(p *corev1.Pod, root string) string {
	if root == "" {
		return ""
	}
	uidDash := string(p.UID)
	uidUnder := strings.ReplaceAll(uidDash, "-", "_")
	qos := strings.ToLower(string(p.Status.QOSClass))
	if qos == "" {
		qos = "besteffort"
	}

	// The slice-prefix is the leaf of the discovered root with .slice
	// stripped.
	leaf := filepath.Base(root)
	prefix := strings.TrimSuffix(leaf, ".slice")

	candidates := []string{
		filepath.Join(root,
			prefix+"-"+qos+".slice",
			prefix+"-"+qos+"-pod"+uidUnder+".slice",
		),
		filepath.Join(root,
			prefix+"-pod"+uidUnder+".slice",
		),
		filepath.Join(root, qos, "pod"+uidDash),
		filepath.Join(root, "pod"+uidDash),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// cgroupIDFromPath returns the inode of a cgroup path — the ID the
// kernel exposes on eBPF events.
func cgroupIDFromPath(path string) (uint64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return 0, fmt.Errorf("unsupported stat type for %s", path)
	}
	return sys.Ino, nil
}

// buildTargetSet turns the active rule set into a tracer.TargetSet.
func buildTargetSet(rules []CRRule, pods []*corev1.Pod) tracer.TargetSet {
	seen := map[uint64]struct{}{}
	var out tracer.TargetSet
	root := discoverKubepodsRoot()

	for _, rule := range rules {
		for id := range rule.CgroupIDs {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			for _, p := range pods {
				path := cgroupPathForPod(p, root)
				if path == "" {
					continue
				}
				pid, err := cgroupIDFromPath(path)
				if err != nil || pid != id {
					continue
				}
				out = append(out, tracer.Target{
					PodName:    p.Name,
					Namespace:  p.Namespace,
					CgroupPath: path,
					Labels:     copyMap(p.Labels),
					PodIP:      p.Status.PodIP,
				})
				break
			}
		}
	}
	return out
}

// filtersToSet converts the CRD's EventFilter list into the
// EventType-keyed set the router needs.
func filtersToSet(in []podtracev1alpha1.EventFilter) map[events.EventType]struct{} {
	out := map[events.EventType]struct{}{}
	for _, f := range in {
		for _, et := range filterToEventTypes(f) {
			out[et] = struct{}{}
		}
	}
	return out
}

// filterToEventTypes expands a high-level filter category into the set
// of low-level EventType values the tracer produces for that category.
func filterToEventTypes(f podtracev1alpha1.EventFilter) []events.EventType {
	switch f {
	case podtracev1alpha1.FilterDNS:
		return []events.EventType{events.EventDNS}
	case podtracev1alpha1.FilterNet:
		return []events.EventType{
			events.EventConnect, events.EventTCPSend, events.EventTCPRecv,
			events.EventUDPSend, events.EventUDPRecv, events.EventTCPState,
			events.EventTCPRetrans, events.EventNetDevError,
			events.EventFastCGIReq, events.EventFastCGIResp,
		}
	case podtracev1alpha1.FilterFS:
		return []events.EventType{
			events.EventOpen, events.EventClose, events.EventRead,
			events.EventWrite, events.EventFsync,
		}
	case podtracev1alpha1.FilterCPU:
		return []events.EventType{events.EventSchedSwitch, events.EventLockContention}
	case podtracev1alpha1.FilterProc:
		return []events.EventType{events.EventExec, events.EventFork, events.EventOOMKill}
	default:
		return nil
	}
}

// copyMap returns a defensive shallow copy of a string map.
func copyMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// podChangePredicates filters Pod watches down to events that actually
// affect matching: label changes (selector matching), phase changes
// (Running-ness), and deletions.
func podChangePredicates() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return true },
		DeleteFunc:  func(e event.DeleteEvent) bool { return true },
		GenericFunc: func(e event.GenericEvent) bool { return false },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldP, ok1 := e.ObjectOld.(*corev1.Pod)
			newP, ok2 := e.ObjectNew.(*corev1.Pod)
			if !ok1 || !ok2 {
				return false
			}
			if oldP.Status.Phase != newP.Status.Phase {
				return true
			}
			if !labelsEqual(oldP.Labels, newP.Labels) {
				return true
			}
			return false
		},
	}
}

func labelsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
