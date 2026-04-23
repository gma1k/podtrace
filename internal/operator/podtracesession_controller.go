package operator

import (
	"context"
	"fmt"
	"sort"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// PodTraceSessionReconciler turns a PodTraceSession CR into one Job per
// node hosting at least one matched pod. Jobs invoke the standalone
// `podtrace --diagnose <duration>` CLI, so session execution is
// decoupled from the DaemonSet agent's lifecycle.
//
// The reconcile loop is intentionally one-shot: once Jobs exist we only
// roll up their status. The only mutating action after initial fan-out
// is TTL-driven cleanup.
type PodTraceSessionReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	SystemNamespace string
}

// +kubebuilder:rbac:groups=podtrace.io,resources=podtracesessions,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=podtrace.io,resources=podtracesessions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=podtrace.io,resources=podtracesessions/finalizers,verbs=update
// +kubebuilder:rbac:groups=podtrace.io,resources=tracerconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=podtrace.io,resources=exporterconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

// Reconcile fans a PodTraceSession out into per-node Jobs, then rolls
// Job status back into PodTraceSession.status.
func (r *PodTraceSessionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("podtracesession", req.String())

	var session podtracev1alpha1.PodTraceSession
	if err := r.Get(ctx, req.NamespacedName, &session); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get PodTraceSession: %w", err)
	}

	// Deletion path: clean up cross-namespace Jobs, then release the finalizer.
	if !session.DeletionTimestamp.IsZero() {
		if err := cleanupPodTraceSessionChildren(ctx, r.Client, &session, r.SystemNamespace); err != nil {
			return ctrl.Result{}, err
		}
		if removeFinalizer(&session) {
			if err := r.Update(ctx, &session); err != nil {
				return ctrl.Result{}, fmt.Errorf("clear finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}
	if ensureFinalizer(&session) {
		if err := r.Update(ctx, &session); err != nil {
			return ctrl.Result{}, fmt.Errorf("set finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Terminal phases are sticky. TTL-driven cleanup runs below, but we
	// do not re-fan out a session that has already produced Jobs.
	if session.Status.Phase == podtracev1alpha1.SessionPhaseCompleted ||
		session.Status.Phase == podtracev1alpha1.SessionPhaseFailed {
		return r.reconcileTerminalSession(ctx, &session)
	}

	targetNodes, err := r.resolveTargetNodes(ctx, &session)
	if err != nil {
		r.setCondition(&session, ConditionDegraded, metav1.ConditionTrue, "ResolveTargets", err.Error())
		_ = r.Status().Update(ctx, &session)
		return ctrl.Result{}, err
	}
	if len(targetNodes) == 0 {
		logger.Info("no matched pods; session stays Pending until pods appear")
		session.Status.Phase = podtracev1alpha1.SessionPhasePending
		r.setCondition(&session, ConditionReconciled, metav1.ConditionTrue, "NoMatchedPods", "selector matched zero pods")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, r.Status().Update(ctx, &session)
	}

	tc := r.resolveTracerConfig(ctx)
	cap := effectiveMaxConcurrentSessionsPerNode(tc)

	if cap > 0 {
		exceeded, err := r.nodesAtCapacity(ctx, targetNodes, cap, session.Namespace, session.Name)
		if err != nil {
			return ctrl.Result{}, err
		}
		if len(exceeded) > 0 {
			r.setCondition(&session, ConditionDegraded, metav1.ConditionTrue, "NodeCapacity",
				fmt.Sprintf("nodes at max concurrency (%d): %v", cap, exceeded))
			_ = r.Status().Update(ctx, &session)
			return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
		}
	}

	jobs, err := r.ensureJobs(ctx, &session, tc, targetNodes)
	if err != nil {
		r.setCondition(&session, ConditionDegraded, metav1.ConditionTrue, "EnsureJobs", err.Error())
		_ = r.Status().Update(ctx, &session)
		return ctrl.Result{}, err
	}

	// Refresh status from Job conditions. summarizeSessionJobs also decides
	// whether the session has reached a terminal phase.
	session.Status.Jobs = makeSessionJobRefs(jobs)
	session.Status.Phase = computeSessionPhase(jobs)
	session.Status.ObservedGeneration = session.Generation
	if session.Status.StartTime == nil && anyJobStarted(jobs) {
		now := metav1.Now()
		session.Status.StartTime = &now
	}
	if isTerminal(session.Status.Phase) && session.Status.CompletionTime == nil {
		now := metav1.Now()
		session.Status.CompletionTime = &now
	}
	r.setCondition(&session, ConditionReconciled, metav1.ConditionTrue, "Reconciled",
		fmt.Sprintf("%d Job(s) on %d node(s)", len(jobs), len(targetNodes)))
	r.setCondition(&session, ConditionDegraded, metav1.ConditionFalse, "Reconciled", "")

	if err := r.Status().Update(ctx, &session); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}

	// Re-queue while the session is still running so status reflects Job
	// progress without waiting on a default 10h informer re-list.
	if !isTerminal(session.Status.Phase) {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	return ctrl.Result{}, nil
}

func (r *PodTraceSessionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("podtracesession").
		For(&podtracev1alpha1.PodTraceSession{}).
		WithOptions(defaultControllerOptions()).
		Complete(r)
}

// resolveTargetNodes expands spec.selector / spec.podRefs into the set of
// node names hosting at least one matched pod. Deterministic ordering
// (sorted) so reconcile is idempotent under flaky informer caches.
func (r *PodTraceSessionReconciler) resolveTargetNodes(ctx context.Context, s *podtracev1alpha1.PodTraceSession) ([]string, error) {
	nodes := map[string]struct{}{}

	if s.Spec.Selector != nil {
		sel, err := metav1.LabelSelectorAsSelector(s.Spec.Selector)
		if err != nil {
			return nil, fmt.Errorf("invalid selector: %w", err)
		}
		var list corev1.PodList
		listOpts := &client.ListOptions{
			LabelSelector: sel,
			Namespace:     s.Namespace,
		}
		if s.Spec.NamespaceSelector != nil {
			// NamespaceSelector opens cross-namespace search. The
			// selector's own label expressions are not yet honoured —
			// that would require a Namespace informer we do not wire
			// here. Presence of the field alone is enough to widen
			// scope to every namespace.
			listOpts.Namespace = ""
		}
		if err := r.List(ctx, &list, listOpts); err != nil {
			return nil, fmt.Errorf("list pods for selector: %w", err)
		}
		for _, p := range list.Items {
			if p.Spec.NodeName != "" && isPodEligible(&p) {
				nodes[p.Spec.NodeName] = struct{}{}
			}
		}
	}

	for _, ref := range s.Spec.PodRefs {
		ns := ref.Namespace
		if ns == "" {
			ns = s.Namespace
		}
		var pod corev1.Pod
		if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, &pod); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("get pod %s/%s: %w", ns, ref.Name, err)
		}
		if pod.Spec.NodeName != "" && isPodEligible(&pod) {
			nodes[pod.Spec.NodeName] = struct{}{}
		}
	}

	out := make([]string, 0, len(nodes))
	for n := range nodes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// isPodEligible filters out pods the tracer cannot attach to: those in
// Pending (no pid/cgroup yet) or already terminated.
func isPodEligible(p *corev1.Pod) bool {
	switch p.Status.Phase {
	case corev1.PodRunning:
		return true
	default:
		return false
	}
}

// resolveTracerConfig returns the "default" TracerConfig when present,
// otherwise nil. A missing TracerConfig is not fatal for session
// reconciliation — defaults are applied — it only means certain caps
// (like MaxConcurrentSessionsPerNode) do not apply.
func (r *PodTraceSessionReconciler) resolveTracerConfig(ctx context.Context) *podtracev1alpha1.TracerConfig {
	var tc podtracev1alpha1.TracerConfig
	if err := r.Get(ctx, types.NamespacedName{Name: "default"}, &tc); err != nil {
		return nil
	}
	return &tc
}

// nodesAtCapacity returns the subset of the candidate node list whose
// current active-session Job count is >= cap. "Active" excludes the
// session currently being reconciled (its own Jobs don't count against
// its own cap). Self-identity is (selfNS, selfName), which is unique
// cluster-wide for PodTraceSession resources.
func (r *PodTraceSessionReconciler) nodesAtCapacity(ctx context.Context, candidates []string, cap int32, selfNS, selfName string) ([]string, error) {
	var allJobs batchv1.JobList
	if err := r.List(ctx, &allJobs, client.MatchingLabels{
		LabelManagedBy: ManagedByValue,
		LabelComponent: ComponentSession,
	}); err != nil {
		return nil, fmt.Errorf("list session Jobs: %w", err)
	}

	counts := map[string]int32{}
	for _, j := range allJobs.Items {
		if j.Status.Succeeded > 0 || j.Status.Failed > 0 {
			continue
		}
		if j.Labels[LabelSessionName] == selfName && j.Labels[LabelSessionNS] == selfNS {
			continue
		}
		node, ok := j.Labels[LabelNodeName]
		if !ok {
			continue
		}
		counts[node]++
	}

	var over []string
	for _, n := range candidates {
		if counts[n] >= cap {
			over = append(over, n)
		}
	}
	return over, nil
}

// effectiveMaxConcurrentSessionsPerNode returns the cap from TracerConfig
// or a sensible default (0 = no cap) when no TracerConfig exists.
func effectiveMaxConcurrentSessionsPerNode(tc *podtracev1alpha1.TracerConfig) int32 {
	if tc == nil {
		return 0
	}
	return tc.Spec.MaxConcurrentSessionsPerNode
}

// ensureJobs creates-or-updates one Job per target node, owner-ref'd to
// the session. Returns all Jobs currently owned by the session (not just
// those created this call) so Reconcile can roll up status.
func (r *PodTraceSessionReconciler) ensureJobs(ctx context.Context, s *podtracev1alpha1.PodTraceSession, tc *podtracev1alpha1.TracerConfig, nodes []string) ([]batchv1.Job, error) {
	systemNS := systemNamespaceForSession(tc, r.SystemNamespace)

	for _, node := range nodes {
		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:      SessionJobName(s.UID, node),
				Namespace: systemNS,
			},
		}
		if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, job, func() error {
			job.Labels = mergeLabels(job.Labels, map[string]string{
				LabelManagedBy:   ManagedByValue,
				LabelComponent:   ComponentSession,
				LabelSessionName: s.Name,
				LabelSessionNS:   s.Namespace,
				LabelNodeName:    node,
			})
			// Spec is immutable after Job creation apart from specific fields;
			// controllerutil.CreateOrUpdate will call us with the existing
			// object, so we only set Spec when it is the zero value (fresh create).
			if job.Spec.Template.Spec.Containers == nil {
				job.Spec = buildSessionJobSpec(s, tc, node)
			}
			// No ownerReference: the PodTraceSession lives in the user
			// namespace but its Jobs live in podtrace-system. Cleanup goes
			// through FinalizerCleanup; see finalizer.go.
			return nil
		}); err != nil {
			return nil, fmt.Errorf("ensure Job for node %s: %w", node, err)
		}
	}

	var owned batchv1.JobList
	if err := r.List(ctx, &owned, client.InNamespace(systemNS), client.MatchingLabels{
		LabelManagedBy:   ManagedByValue,
		LabelComponent:   ComponentSession,
		LabelSessionName: s.Name,
		LabelSessionNS:   s.Namespace,
	}); err != nil {
		return nil, fmt.Errorf("list owned Jobs: %w", err)
	}
	return owned.Items, nil
}

// reconcileTerminalSession handles TTL-driven cleanup only. Terminal
// sessions are not re-fanned-out; we just check if their TTL has
// elapsed and delete the CR.
func (r *PodTraceSessionReconciler) reconcileTerminalSession(ctx context.Context, s *podtracev1alpha1.PodTraceSession) (ctrl.Result, error) {
	ttl := sessionTTL(s)
	if ttl == 0 || s.Status.CompletionTime == nil {
		return ctrl.Result{}, nil
	}
	deadline := s.Status.CompletionTime.Add(time.Duration(ttl) * time.Second)
	if time.Now().Before(deadline) {
		return ctrl.Result{RequeueAfter: time.Until(deadline)}, nil
	}
	if err := r.Delete(ctx, s); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("delete expired session: %w", err)
	}
	return ctrl.Result{}, nil
}

func sessionTTL(s *podtracev1alpha1.PodTraceSession) int32 {
	if s.Spec.TTLSecondsAfterFinished != nil {
		return *s.Spec.TTLSecondsAfterFinished
	}
	return 300
}

// setCondition mirrors TracerConfigReconciler.setCondition; duplicated
// rather than generic so the two reconcilers can evolve independently.
func (r *PodTraceSessionReconciler) setCondition(s *podtracev1alpha1.PodTraceSession, condType string, status metav1.ConditionStatus, reason, message string) {
	s.Status.Conditions = upsertCondition(s.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: s.Generation,
	})
}

func systemNamespaceForSession(tc *podtracev1alpha1.TracerConfig, fallback string) string {
	if tc != nil && tc.Spec.SystemNamespace != "" {
		return tc.Spec.SystemNamespace
	}
	return fallback
}

