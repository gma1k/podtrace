package operator

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUpsertCondition_AppendsNewType(t *testing.T) {
	now := metav1.Now()
	conds := upsertCondition(nil, metav1.Condition{
		Type:               ConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             "ok",
		LastTransitionTime: now,
	})
	if len(conds) != 1 || conds[0].Type != ConditionReady {
		t.Fatalf("unexpected conds: %+v", conds)
	}
}

func TestUpsertCondition_UpdatesSameType(t *testing.T) {
	oldTime := metav1.NewTime(time.Now().Add(-time.Hour))
	conds := []metav1.Condition{{
		Type:               ConditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             "old",
		LastTransitionTime: oldTime,
	}}
	newer := metav1.Condition{
		Type:               ConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             "new",
		LastTransitionTime: metav1.Now(),
	}
	conds = upsertCondition(conds, newer)
	if len(conds) != 1 {
		t.Fatalf("upsert grew the slice: %+v", conds)
	}
	if conds[0].Reason != "new" || conds[0].Status != metav1.ConditionTrue {
		t.Errorf("condition not updated: %+v", conds[0])
	}
}

func TestUpsertCondition_PreservesTransitionWhenStatusUnchanged(t *testing.T) {
	// Kubernetes-condition invariant: LastTransitionTime only changes
	// when Status changes. A reconcile that re-reports the same Status
	// must not bump the timestamp — consumers use that timestamp as a
	// "how long has this been true" signal.
	oldTime := metav1.NewTime(time.Now().Add(-time.Hour))
	conds := []metav1.Condition{{
		Type:               ConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             "previous",
		LastTransitionTime: oldTime,
	}}
	same := metav1.Condition{
		Type:               ConditionReady,
		Status:             metav1.ConditionTrue, // unchanged
		Reason:             "refreshed",
		LastTransitionTime: metav1.Now(),
	}
	conds = upsertCondition(conds, same)
	if !conds[0].LastTransitionTime.Equal(&oldTime) {
		t.Errorf("LastTransitionTime changed despite same Status: %v → %v",
			oldTime, conds[0].LastTransitionTime)
	}
}

func TestMergeLabels(t *testing.T) {
	got := mergeLabels(nil, map[string]string{"a": "1"})
	if got["a"] != "1" {
		t.Errorf("merge into nil failed: %v", got)
	}
	got = mergeLabels(map[string]string{"a": "1", "b": "2"}, map[string]string{"b": "new", "c": "3"})
	if got["a"] != "1" || got["b"] != "new" || got["c"] != "3" {
		t.Errorf("merge wrong: %v", got)
	}
}

func TestConditionStatusFromBool(t *testing.T) {
	if conditionStatusFromBool(true) != metav1.ConditionTrue {
		t.Error("true should map to ConditionTrue")
	}
	if conditionStatusFromBool(false) != metav1.ConditionFalse {
		t.Error("false should map to ConditionFalse")
	}
}
