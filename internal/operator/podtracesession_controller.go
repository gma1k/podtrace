package operator

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// PodTraceSessionReconciler turns a PodTraceSession CR into one Job per
// node hosting at least one matched pod.
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
// +kubebuilder:rbac:groups=core,resources=configmaps;secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch;delete

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

	if !session.DeletionTimestamp.IsZero() {
		tc, err := r.resolveTracerConfig(ctx)
		if err != nil {
			logger.Info("TracerConfig unreadable during session deletion; using fallback system namespace for cleanup", "error", err.Error())
			tc = nil
		}
		sessionNS := systemNamespaceForSession(tc, r.SystemNamespace)
		for _, ns := range candidateSystemNamespaces(sessionNS, r.SystemNamespace) {
			if err := cleanupPodTraceSessionChildren(ctx, r.Client, &session, ns); err != nil {
				return ctrl.Result{}, err
			}
		}
		forgetReportObservations(session.Namespace, session.Name)
		if removeFinalizer(&session) {
			if err := r.Update(ctx, &session); err != nil {
				if res, handled := finalizerUpdateOutcome(err); handled {
					return res, nil
				}
				return ctrl.Result{}, fmt.Errorf("clear finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}
	if ensureFinalizer(&session) {
		if err := r.Update(ctx, &session); err != nil {
			if res, handled := finalizerUpdateOutcome(err); handled {
				return res, nil
			}
			return ctrl.Result{}, fmt.Errorf("set finalizer: %w", err)
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	if session.Status.State == podtracev1alpha1.SessionStateCompleted ||
		session.Status.State == podtracev1alpha1.SessionStateFailed {
		return r.reconcileTerminalSession(ctx, &session)
	}

	if session.Spec.ReportRef != nil && session.Spec.ReportRef.ObjectStore != nil {
		if err := podtracev1alpha1.ValidateObjectStoreReference(session.Spec.ReportRef.ObjectStore); err != nil {
			return ctrl.Result{}, r.failSessionTerminally(ctx, &session, "ObjectStoreURIInvalid", err.Error())
		}
	}

	targets, err := r.resolveSessionTargets(ctx, &session)
	if err != nil {
		if strings.Contains(err.Error(), "invalid NamespaceSelector") {
			return ctrl.Result{}, r.failSessionTerminally(ctx, &session, "NamespaceSelectorInvalid", err.Error())
		}
		r.setCondition(&session, ConditionDegraded, metav1.ConditionTrue, "ResolveTargets", err.Error())
		_ = r.Status().Update(ctx, &session)
		return ctrl.Result{}, err
	}
	session.Status.TargetNamespaces = targets.Namespaces
	if len(targets.Nodes) == 0 {
		reason, message := "NoMatchedPods", "selector matched zero pods"
		if len(targets.DeniedNamespaces) > 0 {
			reason = "CrossNamespaceNotGranted"
			message = crossNamespaceDeniedMessage(session.Namespace, targets.DeniedNamespaces)
		}
		logger.Info("no matched pods; session stays Pending until pods appear", "reason", reason)
		session.Status.State = podtracev1alpha1.SessionStatePending
		r.setCondition(&session, ConditionReconciled, metav1.ConditionTrue, reason, message)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, r.Status().Update(ctx, &session)
	}

	tc, err := r.resolveTracerConfig(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	systemNS := systemNamespaceForSession(tc, r.SystemNamespace)

	var ec podtracev1alpha1.ExporterConfig
	ecKey := types.NamespacedName{Namespace: session.Namespace, Name: session.Spec.ExporterRef.Name}
	if err := r.Get(ctx, ecKey, &ec); err != nil {
		if apierrors.IsNotFound(err) {
			r.setCondition(&session, ConditionDegraded, metav1.ConditionTrue, "ExporterNotFound",
				fmt.Sprintf("ExporterConfig %s not found", ecKey))
			_ = r.Status().Update(ctx, &session)
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get ExporterConfig: %w", err)
	}
	if err := ensureSessionExporterBundle(ctx, r.Client, &session, &ec, systemNS); err != nil {
		r.setCondition(&session, ConditionDegraded, metav1.ConditionTrue, "BundleSync", err.Error())
		_ = r.Status().Update(ctx, &session)
		return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
	}

	if _, err := ensureSessionObjectStoreCredentials(ctx, r.Client, &session, systemNS); err != nil {
		r.setCondition(&session, ConditionDegraded, metav1.ConditionTrue, "ObjectStoreCreds", err.Error())
		_ = r.Status().Update(ctx, &session)
		return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
	}

	if err := ensureSessionServiceAccount(ctx, r.Client, &session, systemNS); err != nil {
		r.setCondition(&session, ConditionDegraded, metav1.ConditionTrue, "SessionSA", err.Error())
		_ = r.Status().Update(ctx, &session)
		return ctrl.Result{}, err
	}
	if err := ensureSessionReportObject(ctx, r.Client, &session); err != nil {
		var conflict *reportObjectConflictError
		if errors.As(err, &conflict) {
			return ctrl.Result{}, r.failSessionTerminally(ctx, &session, "ReportObjectConflict", err.Error())
		}
		r.setCondition(&session, ConditionDegraded, metav1.ConditionTrue, "SessionRBAC", err.Error())
		_ = r.Status().Update(ctx, &session)
		return ctrl.Result{}, err
	}
	if err := ensureSessionReportRBAC(ctx, r.Client, &session, systemNS); err != nil {
		r.setCondition(&session, ConditionDegraded, metav1.ConditionTrue, "SessionRBAC", err.Error())
		_ = r.Status().Update(ctx, &session)
		return ctrl.Result{}, err
	}
	if err := ensureSessionPodReadRBAC(ctx, r.Client, &session, sessionPodNamespaces(&session, targets), systemNS); err != nil {
		r.setCondition(&session, ConditionDegraded, metav1.ConditionTrue, "SessionRBAC", err.Error())
		_ = r.Status().Update(ctx, &session)
		return ctrl.Result{}, err
	}

	cap := effectiveMaxConcurrentSessionsPerNode(tc)

	if cap > 0 {
		exceeded, err := r.nodesAtCapacity(ctx, targets.Nodes, cap, session.Namespace, session.Name)
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

	completedNodes := completedSessionNodes(session.Status.Jobs)
	jobs, err := r.ensureJobs(ctx, &session, tc, targets, completedNodes)
	if err != nil {
		r.setCondition(&session, ConditionDegraded, metav1.ConditionTrue, "EnsureJobs", err.Error())
		_ = r.Status().Update(ctx, &session)
		return ctrl.Result{}, err
	}

	session.Status.Jobs = mergeSessionJobRefs(jobs, session.Status.Jobs)
	session.Status.State = computeSessionState(session.Status.Jobs, jobs, len(targets.Nodes))
	session.Status.ObservedGeneration = session.Generation

	if err := populateSessionSummaries(ctx, r.Client, &session, jobs); err != nil {
		return ctrl.Result{}, err
	}
	if session.Status.StartTime == nil && anyJobStarted(jobs) {
		now := metav1.Now()
		session.Status.StartTime = &now
	}
	if isTerminal(session.Status.State) && session.Status.CompletionTime == nil {
		now := metav1.Now()
		session.Status.CompletionTime = &now
	}
	reconciledMessage := fmt.Sprintf("%d Job(s) on %d node(s)", len(jobs), len(targets.Nodes))
	if len(targets.DeniedNamespaces) > 0 {
		reconciledMessage += "; " + crossNamespaceDeniedMessage(session.Namespace, targets.DeniedNamespaces)
	}
	r.setCondition(&session, ConditionReconciled, metav1.ConditionTrue, "Reconciled", reconciledMessage)
	r.setCondition(&session, ConditionDegraded, metav1.ConditionFalse, "Reconciled", "")

	if obs, err := harvestReportLocation(ctx, r.Client, &session, systemNS); err != nil {
		logger.Error(err, "harvest report location")
	} else {
		applyReportUploadStatus(&session, obs)
		observeReportUploadMetrics(&session, obs)
	}

	if err := r.Status().Update(ctx, &session); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}

	if !isTerminal(session.Status.State) {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	return ctrl.Result{}, nil
}

func (r *PodTraceSessionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("podtracesession").
		For(&podtracev1alpha1.PodTraceSession{}).
		Watches(
			&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(r.namespaceToPodTraceSessions),
		).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.secretToPodTraceSessions),
		).
		WithOptions(defaultControllerOptions()).
		Complete(r)
}

// secretToPodTraceSessions maps a Secret event to the non-terminal
// PodTraceSessions whose ExporterConfig references that Secret.
func (r *PodTraceSessionReconciler) secretToPodTraceSessions(ctx context.Context, obj client.Object) []reconcile.Request {
	ecs := exporterConfigsReferencingSecret(ctx, r.Client, obj)
	if len(ecs) == 0 {
		return nil
	}
	referenced := make(map[string]struct{}, len(ecs))
	for i := range ecs {
		referenced[ecs[i].Name] = struct{}{}
	}
	var list podtracev1alpha1.PodTraceSessionList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		s := &list.Items[i]
		if s.Status.State == podtracev1alpha1.SessionStateCompleted ||
			s.Status.State == podtracev1alpha1.SessionStateFailed {
			continue
		}
		if _, ok := referenced[s.Spec.ExporterRef.Name]; ok {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: client.ObjectKey{Namespace: s.Namespace, Name: s.Name},
			})
		}
	}
	return reqs
}

// namespaceToPodTraceSessions returns the set of PodTraceSessions
// that should re-reconcile when any Namespace event fires.
func (r *PodTraceSessionReconciler) namespaceToPodTraceSessions(ctx context.Context, _ client.Object) []reconcile.Request {
	var list podtracev1alpha1.PodTraceSessionList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		s := &list.Items[i]
		if s.Spec.NamespaceSelector == nil {
			continue
		}
		if s.Status.State == podtracev1alpha1.SessionStateCompleted ||
			s.Status.State == podtracev1alpha1.SessionStateFailed {
			continue
		}
		out = append(out, reconcile.Request{
			NamespacedName: client.ObjectKey{Namespace: s.Namespace, Name: s.Name},
		})
	}
	return out
}

// sessionTargets is the grant-authorized view of a session's targets.
// Everything downstream, node fan-out, Job arguments, per-namespace
// pod-read RBAC, must derive from this struct, never from the raw
// spec, so the tenancy boundary is enforced in exactly one place.
type sessionTargets struct {
	Nodes            []string
	Namespaces       []string
	PodRefs          []podtracev1alpha1.PodRef
	DeniedNamespaces []string
}

// resolveSessionTargets expands spec.selector / spec.podRefs into the
// set of node names hosting at least one matched pod, restricted to
// namespaces the session is authorized to target.
func (r *PodTraceSessionReconciler) resolveSessionTargets(ctx context.Context, s *podtracev1alpha1.PodTraceSession) (sessionTargets, error) {
	nodes := map[string]struct{}{}

	targetNamespaces, deniedNamespaces, err := ResolveNamespaceSelector(ctx, r.Client, s.Spec.NamespaceSelector, s.Namespace)
	if err != nil {
		return sessionTargets{}, err
	}
	if s.Spec.Selector == nil {
		targetNamespaces, deniedNamespaces = nil, nil
	}

	allowedPodRefs, deniedRefNamespaces, err := filterGrantedPodRefs(ctx, r.Client, s.Namespace, s.Spec.PodRefs)
	if err != nil {
		return sessionTargets{}, err
	}
	deniedNamespaces = mergeSortedNamespaceSets(deniedNamespaces, deniedRefNamespaces)

	if s.Spec.Selector != nil {
		sel, err := metav1.LabelSelectorAsSelector(s.Spec.Selector)
		if err != nil {
			return sessionTargets{}, fmt.Errorf("invalid selector: %w", err)
		}

		// Allowlist drives the namespace scope. Three cases:
		//
		//   targetNamespaces == nil  → selector unset on the CR; restrict
		//                              to the session's own namespace.
		//   targetNamespaces empty   → selector set but no namespaces
		//                              match; skip the List entirely (no
		//                              pods can be selected).
		//   targetNamespaces non-empty → list cluster-wide and filter the
		//                              results in-memory against the set.
		//
		// In-memory filtering after a cluster-wide List is cheaper than N
		// per-namespace Lists when the cached informer is cluster-scoped
		// (which it is for our manager).
		switch {
		case targetNamespaces == nil:
			listOpts := &client.ListOptions{LabelSelector: sel, Namespace: s.Namespace}
			var list corev1.PodList
			if err := r.List(ctx, &list, listOpts); err != nil {
				return sessionTargets{}, fmt.Errorf("list pods for selector: %w", err)
			}
			for _, p := range list.Items {
				if p.Spec.NodeName != "" && isPodEligible(&p) {
					nodes[p.Spec.NodeName] = struct{}{}
				}
			}
		case len(targetNamespaces) == 0:
		default:
			allowSet := make(map[string]struct{}, len(targetNamespaces))
			for _, ns := range targetNamespaces {
				allowSet[ns] = struct{}{}
			}
			listOpts := &client.ListOptions{LabelSelector: sel} // Namespace empty == cluster-wide
			var list corev1.PodList
			if err := r.List(ctx, &list, listOpts); err != nil {
				return sessionTargets{}, fmt.Errorf("list pods for selector: %w", err)
			}
			for _, p := range list.Items {
				if _, ok := allowSet[p.Namespace]; !ok {
					continue
				}
				if p.Spec.NodeName != "" && isPodEligible(&p) {
					nodes[p.Spec.NodeName] = struct{}{}
				}
			}
		}
	}

	for _, ref := range allowedPodRefs {
		ns := ref.Namespace
		if ns == "" {
			ns = s.Namespace
		}
		var pod corev1.Pod
		if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, &pod); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return sessionTargets{}, fmt.Errorf("get pod %s/%s: %w", ns, ref.Name, err)
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
	return sessionTargets{
		Nodes:            out,
		Namespaces:       targetNamespaces,
		PodRefs:          allowedPodRefs,
		DeniedNamespaces: deniedNamespaces,
	}, nil
}

// mergeSortedNamespaceSets unions two sorted namespace lists, keeping
// the result sorted and duplicate-free. Both inputs may be nil.
func mergeSortedNamespaceSets(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	set := make(map[string]struct{}, len(a)+len(b))
	for _, ns := range a {
		set[ns] = struct{}{}
	}
	for _, ns := range b {
		set[ns] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for ns := range set {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
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

// failSessionTerminally marks a session Failed with a CompletionTime stamp.
func (r *PodTraceSessionReconciler) failSessionTerminally(ctx context.Context, s *podtracev1alpha1.PodTraceSession, reason, message string) error {
	s.Status.State = podtracev1alpha1.SessionStateFailed
	if s.Status.CompletionTime == nil {
		now := metav1.Now()
		s.Status.CompletionTime = &now
	}
	r.setCondition(s, ConditionDegraded, metav1.ConditionTrue, reason, message)
	return r.Status().Update(ctx, s)
}

// resolveTracerConfig returns the "default" TracerConfig when present.
func (r *PodTraceSessionReconciler) resolveTracerConfig(ctx context.Context) (*podtracev1alpha1.TracerConfig, error) {
	var tc podtracev1alpha1.TracerConfig
	if err := r.Get(ctx, types.NamespacedName{Name: DefaultTracerConfigName}, &tc); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get TracerConfig %q: %w", DefaultTracerConfigName, err)
	}
	return &tc, nil
}

// nodesAtCapacity returns the subset of the candidate node list whose
// current active-session Job count is >= cap.
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
// the session.
func (r *PodTraceSessionReconciler) ensureJobs(ctx context.Context, s *podtracev1alpha1.PodTraceSession, tc *podtracev1alpha1.TracerConfig, targets sessionTargets, completedNodes map[string]struct{}) ([]batchv1.Job, error) {
	systemNS := systemNamespaceForSession(tc, r.SystemNamespace)

	for _, node := range targets.Nodes {
		if _, done := completedNodes[node]; done {
			continue
		}
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
			if job.Spec.Template.Spec.Containers == nil {
				job.Spec = buildSessionJobSpec(s, tc, node, targets)
			}
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

// reconcileTerminalSession handles TTL-driven cleanup only.
func (r *PodTraceSessionReconciler) reconcileTerminalSession(ctx context.Context, s *podtracev1alpha1.PodTraceSession) (ctrl.Result, error) {
	if s.Status.CompletionTime == nil {
		return ctrl.Result{}, nil
	}
	ttl := sessionTTL(s)
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

// setCondition mirrors TracerConfigReconciler.setCondition.
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
