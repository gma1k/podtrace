package operator

import (
	"context"
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

const (
	defaultReaperInterval = 15 * time.Minute
	defaultReaperGrace    = 10 * time.Minute
)

// SessionChildReaper is the finalizer-bypass backstop for a PodTraceSession's
// cross-namespace children (per-node Jobs, exporter bundle, objectStore creds,
// ServiceAccount, and cross-namespace pod-read RBAC). Those objects live in a
// namespace the session cannot own via ownerReferences, so if the
// podtrace.io/cleanup finalizer is stripped or the operator is down at deletion
// time, nothing garbage-collects them. This Runnable periodically deletes any
// such child whose owning session no longer exists.
type SessionChildReaper struct {
	Client   client.Client
	Interval time.Duration
	Grace    time.Duration
}

// NeedLeaderElection keeps the sweep on a single replica.
func (r *SessionChildReaper) NeedLeaderElection() bool { return true }

func (r *SessionChildReaper) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("session-child-reaper")
	interval := r.Interval
	if interval <= 0 {
		interval = defaultReaperInterval
	}
	grace := r.Grace
	if grace <= 0 {
		grace = defaultReaperGrace
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if n, err := reapOrphanSessionChildren(ctx, r.Client, time.Now(), grace); err != nil {
			logger.Error(err, "orphan session-child sweep failed; will retry next tick")
		} else if n > 0 {
			logger.Info("reaped orphaned session children", "count", n)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

type reapCandidate struct {
	obj         client.Object
	sessionNS   string
	sessionName string
}

// reapOrphanSessionChildren lists every operator-managed object that names an
// owning session via labels and deletes those whose session is gone.
func reapOrphanSessionChildren(ctx context.Context, c client.Client, now time.Time, grace time.Duration) (int, error) {
	var candidates []reapCandidate
	consider := func(o client.Object) {
		labels := o.GetLabels()
		sns, sn := labels[LabelSessionNS], labels[LabelSessionName]
		if sns == "" || sn == "" {
			return
		}
		if labels[labelReportKind] == reportKindValue {
			return
		}
		if grace > 0 && now.Sub(o.GetCreationTimestamp().Time) < grace {
			return
		}
		candidates = append(candidates, reapCandidate{obj: o, sessionNS: sns, sessionName: sn})
	}

	sel := client.MatchingLabels{LabelManagedBy: ManagedByValue}

	var jobs batchv1.JobList
	if err := c.List(ctx, &jobs, sel); err != nil {
		return 0, fmt.Errorf("list session Jobs: %w", err)
	}
	for i := range jobs.Items {
		consider(&jobs.Items[i])
	}
	var cms corev1.ConfigMapList
	if err := c.List(ctx, &cms, sel); err != nil {
		return 0, fmt.Errorf("list session ConfigMaps: %w", err)
	}
	for i := range cms.Items {
		consider(&cms.Items[i])
	}
	var secrets corev1.SecretList
	if err := c.List(ctx, &secrets, sel); err != nil {
		return 0, fmt.Errorf("list session Secrets: %w", err)
	}
	for i := range secrets.Items {
		consider(&secrets.Items[i])
	}
	var sas corev1.ServiceAccountList
	if err := c.List(ctx, &sas, sel); err != nil {
		return 0, fmt.Errorf("list session ServiceAccounts: %w", err)
	}
	for i := range sas.Items {
		consider(&sas.Items[i])
	}
	var roles rbacv1.RoleList
	if err := c.List(ctx, &roles, sel); err != nil {
		return 0, fmt.Errorf("list session Roles: %w", err)
	}
	for i := range roles.Items {
		consider(&roles.Items[i])
	}
	var bindings rbacv1.RoleBindingList
	if err := c.List(ctx, &bindings, sel); err != nil {
		return 0, fmt.Errorf("list session RoleBindings: %w", err)
	}
	for i := range bindings.Items {
		consider(&bindings.Items[i])
	}

	type sessionKey struct{ ns, name string }
	alive := map[sessionKey]bool{}
	deleted := 0
	for _, cand := range candidates {
		key := sessionKey{cand.sessionNS, cand.sessionName}
		live, checked := alive[key]
		if !checked {
			var s podtracev1alpha1.PodTraceSession
			err := c.Get(ctx, types.NamespacedName{Namespace: cand.sessionNS, Name: cand.sessionName}, &s)
			switch {
			case err == nil:
				live = true
			case apierrors.IsNotFound(err):
				live = false
			default:
				continue
			}
			alive[key] = live
		}
		if live {
			continue
		}
		if err := c.Delete(ctx, cand.obj); err != nil && !apierrors.IsNotFound(err) {
			return deleted, fmt.Errorf("reap orphan %T %s/%s: %w",
				cand.obj, cand.obj.GetNamespace(), cand.obj.GetName(), err)
		}
		deleted++
	}
	return deleted, nil
}
