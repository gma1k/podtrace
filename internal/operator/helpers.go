package operator

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

// defaultControllerOptions centralises tuning knobs applied to every
// reconciler in the operator. Reconciliation is single-writer per CR
// (MaxConcurrentReconciles=1) — the CRs are few, and concurrent
// reconciliation of the same object would race on status patches.
func defaultControllerOptions() controller.Options {
	return controller.Options{
		MaxConcurrentReconciles: 1,
	}
}

// mergeLabels returns dst with src's entries overlaid. nil-safe: either
// argument may be nil.
func mergeLabels(dst, src map[string]string) map[string]string {
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// upsertCondition replaces the entry in conds with the same Type as
// newCond, or appends newCond if no such entry exists. It preserves the
// original LastTransitionTime when Status is unchanged — the standard
// Kubernetes-condition invariant.
func upsertCondition(conds []metav1.Condition, newCond metav1.Condition) []metav1.Condition {
	for i, c := range conds {
		if c.Type != newCond.Type {
			continue
		}
		if c.Status == newCond.Status {
			newCond.LastTransitionTime = c.LastTransitionTime
		}
		conds[i] = newCond
		return conds
	}
	return append(conds, newCond)
}

// conditionStatusFromBool maps a boolean to metav1.ConditionTrue/False.
// Extracted so readers do not have to parse a ternary at every call site.
func conditionStatusFromBool(ok bool) metav1.ConditionStatus {
	if ok {
		return metav1.ConditionTrue
	}
	return metav1.ConditionFalse
}
