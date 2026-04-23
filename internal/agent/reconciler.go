package agent

import (
	"context"
	"fmt"
	"os"
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

// AgentReconciler is the single controller the agent runs. It listens
// to changes on three resource types — PodTrace (cluster), Pod
// (node-local), and ConfigMap (system-NS bundles) — and rebuilds the
// Router's full rule set from scratch on every tick.
//
// "Rebuild from scratch" rather than incremental deltas is deliberate:
// the rule set is small (usually <10 CRs per cluster, not per node),
// the informer cache is already in memory, and a full rebuild is
// simpler to reason about than a diff loop that has to track
// add/modify/delete per informer.
type AgentReconciler struct {
	client.Client
	NodeName        string
	SystemNamespace string
	Router          *Router
	Metrics         *Metrics

	TargetsCh chan tracer.TargetSet

	// ExporterBuilder is the dependency injection point for
	// BuildExporter. Tests override with a fake exporter factory.
	ExporterBuilder func(payload *BundlePayload, crKey CRKey) (tracer.Exporter, error)

	CgroupResolver func(pods []*corev1.Pod) (map[uint64]struct{}, error)

	// ExporterCache memoizes the tracer.Exporter per CR keyed by
	// bundle ResourceVersion. A bundle ResourceVersion change (e.g.
	// secret rotation) forces a rebuild; a no-op reconcile does not
	// reopen connections.
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

// Reconcile rebuilds the full router rule set. The incoming req is
// used only for logging — every invocation rebuilds everything,
// guaranteeing the router snapshot matches the API server's view at
// any moment in time.
func (r *AgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrllog.FromContext(ctx).WithName("agent").WithValues("nudged_by", req.String())

	if r.Metrics != nil {
		r.Metrics.ReconcileTotal.Inc()
	}

	// --- step 1: list CRs ------------------------------------------------
	var ptList podtracev1alpha1.PodTraceList
	if err := r.List(ctx, &ptList); err != nil {
		return ctrl.Result{}, fmt.Errorf("list PodTrace: %w", err)
	}
	// --- step 2: list local pods ---------------------------------------
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

	// --- step 3: for each CR, match pods → compute cgroups → load bundle
	rules := make([]CRRule, 0, len(ptList.Items))
	activeKeys := make(map[CRKey]struct{}, len(ptList.Items))

	for i := range ptList.Items {
		pt := &ptList.Items[i]
		if pt.Spec.Paused {
			continue
		}
		key := CRKey{Namespace: pt.Namespace, Name: pt.Name}

		matched, err := MatchPodTraceAgainstPods(pt, localPods)
		if err != nil {
			logger.Error(err, "match pods", "cr", key)
			continue
		}
		if len(matched) == 0 {
			// No pods on this node match — release the cached exporter
			// so credential memory does not linger, and skip publishing
			// a rule for this CR.
			r.releaseExporter(key)
			continue
		}

		cgroupIDs, err := r.CgroupResolver(matched)
		if err != nil {
			logger.Error(err, "resolve cgroup IDs", "cr", key)
			continue
		}

		bundle, err := LoadBundle(ctx, r.Client, r.SystemNamespace, pt.UID)
		if err != nil {
			if apierrors.IsNotFound(err) {
				logger.V(1).Info("bundle not yet synced", "cr", key)
				continue
			}
			logger.Error(err, "load bundle", "cr", key)
			continue
		}

		exporter, err := r.obtainExporter(key, bundle)
		if err != nil {
			logger.Error(err, "build exporter", "cr", key)
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

	// Release cached exporters for CRs that dropped off the active set.
	r.reapStaleExporters(activeKeys)

	r.Router.Publish(rules)

	// --- step 4: feed the union cgroup set to the tracer ---------------
	targets := buildTargetSet(rules, localPods)
	select {
	case r.TargetsCh <- targets:
	default:
		// Channel full → keep-latest semantics. Drop one and retry.
		select {
		case <-r.TargetsCh:
		default:
		}
		select {
		case r.TargetsCh <- targets:
		default:
		}
	}

	// --- step 5: refresh metrics view ----------------------------------
	if r.Metrics != nil {
		r.Metrics.RefreshFromRouter(r.Router)
	}

	return ctrl.Result{}, nil
}

// enqueueAllPodTraces turns a Pod event into one reconcile request per
// PodTrace: any pod change can affect any CR's matched set.
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
		// Bundle RV changed: close the old exporter before replacing.
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
// Called when a CR's matched-pod set on this node drops to zero.
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
// number — the value the kernel stamps on every event. Pods with
// unresolvable cgroups are silently skipped (they will return on the
// next reconcile when the kubelet has published a cgroup path).
//
// The agent must run with host PID + cgroup mounts for Stat to reach
// the actual inode; the DaemonSet manifest guarantees this.
func resolveCgroupIDs(pods []*corev1.Pod) (map[uint64]struct{}, error) {
	out := map[uint64]struct{}{}
	for _, p := range pods {
		for _, cs := range p.Status.ContainerStatuses {
			path := cgroupPathForContainer(p, cs.Name)
			if path == "" {
				continue
			}
			id, err := cgroupIDFromPath(path)
			if err != nil {
				continue
			}
			out[id] = struct{}{}
		}
	}
	return out, nil
}

// cgroupPathForContainer returns the best-effort /sys/fs/cgroup path
// for a container inside a pod. The real CRI-aware resolver lives in
// internal/kubernetes and is too heavy for the agent's hot path; the
// heuristic here is slightly-lossy and relies on the reconcile loop
// picking up a pod on a later tick once its cgroup path materializes.
func cgroupPathForContainer(p *corev1.Pod, _ string) string {
	// Systemd cgroup driver emits paths under
	//   /sys/fs/cgroup/kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<UID>.slice
	// kubelet's "cgroupfs" driver emits
	//   /sys/fs/cgroup/kubepods/<qos>/pod<UID>
	// We walk both layouts and return the first that stat()s.
	uid := strings.ReplaceAll(string(p.UID), "-", "_")
	qos := strings.ToLower(string(p.Status.QOSClass))
	if qos == "" {
		qos = "besteffort"
	}

	candidates := []string{
		fmt.Sprintf("/sys/fs/cgroup/kubepods.slice/kubepods-%s.slice/kubepods-%s-pod%s.slice", qos, qos, uid),
		fmt.Sprintf("/sys/fs/cgroup/kubepods/%s/pod%s", qos, string(p.UID)),
		fmt.Sprintf("/sys/fs/cgroup/kubepods.slice/kubepods-pod%s.slice", uid),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// cgroupIDFromPath returns the inode of a cgroup path — the ID the
// kernel exposes on eBPF events. Duplicated from internal/ebpf/tracer
// (where it is unexported) to keep the agent's import graph shallow.
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
// Each Target needs a cgroup path (not ID) for the tracer's
// AttachToCgroup call, so we rebuild paths from local pods here.
func buildTargetSet(rules []CRRule, pods []*corev1.Pod) tracer.TargetSet {
	seen := map[uint64]struct{}{}
	var out tracer.TargetSet

	for _, rule := range rules {
		for id := range rule.CgroupIDs {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			// Find the pod whose cgroup matches this ID, copy its
			// metadata onto the Target so exporters can enrich events.
			for _, p := range pods {
				path := cgroupPathForContainer(p, "")
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
// EventType-keyed set the router needs. Unrecognised names are skipped
// silently: the CRD enum prevents that case in practice.
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
// The mapping is intentionally broad — a CR opting into "net" wants
// TCP + UDP + retransmits, not just TCP send.
func filterToEventTypes(f podtracev1alpha1.EventFilter) []events.EventType {
	switch f {
	case podtracev1alpha1.FilterDNS:
		return []events.EventType{events.EventDNS}
	case podtracev1alpha1.FilterNet:
		return []events.EventType{
			events.EventConnect, events.EventTCPSend, events.EventTCPRecv,
			events.EventUDPSend, events.EventUDPRecv, events.EventTCPState,
			events.EventTCPRetrans, events.EventNetDevError,
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
// (Running-ness), and deletions. Drops spec-only mutations that have
// no bearing on our routing.
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

