package operator

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestConditionsEqual_Branches(t *testing.T) {
	base := []metav1.Condition{
		{Type: "Ready", Status: metav1.ConditionTrue, Reason: "OK", Message: "all good"},
		{Type: "Synced", Status: metav1.ConditionFalse, Reason: "Pending", Message: "waiting"},
	}

	tests := []struct {
		name string
		a    []metav1.Condition
		b    []metav1.Condition
		want bool
	}{
		{
			name: "equal",
			a:    base,
			b:    []metav1.Condition{base[1], base[0]},
			want: true,
		},
		{
			name: "different length",
			a:    base,
			b:    base[:1],
			want: false,
		},
		{
			name: "missing type",
			a:    base,
			b:    []metav1.Condition{base[0], {Type: "Other", Status: metav1.ConditionTrue}},
			want: false,
		},
		{
			name: "status differs",
			a:    base,
			b: []metav1.Condition{
				base[0],
				{Type: "Synced", Status: metav1.ConditionTrue, Reason: "Pending", Message: "waiting"},
			},
			want: false,
		},
		{
			name: "message differs",
			a:    base,
			b: []metav1.Condition{
				base[0],
				{Type: "Synced", Status: metav1.ConditionFalse, Reason: "Pending", Message: "changed"},
			},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := conditionsEqual(tc.a, tc.b); got != tc.want {
				t.Errorf("conditionsEqual() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReportToSpecFromReportRef_ObjectStoreAndNil(t *testing.T) {
	if got := reportToSpecFromReportRef(nil); got != "" {
		t.Errorf("nil session should be empty, got %q", got)
	}

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ReportRef: &podtracev1alpha1.ReportReference{
				ObjectStore: &podtracev1alpha1.ObjectStoreReference{URI: "s3://bucket/key"},
			},
		},
	}
	if got := reportToSpecFromReportRef(s); got != "s3://bucket/key" {
		t.Errorf("objectstore spec: %q", got)
	}

	// ReportRef present but no populated variant falls through to "".
	s.Spec.ReportRef = &podtracev1alpha1.ReportReference{}
	if got := reportToSpecFromReportRef(s); got != "" {
		t.Errorf("empty ref should be empty, got %q", got)
	}
}
