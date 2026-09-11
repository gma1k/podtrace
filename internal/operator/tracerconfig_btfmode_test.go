package operator

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func reconciledMessage(t *testing.T, conditions []metav1.Condition) string {
	t.Helper()
	for _, c := range conditions {
		if c.Type == ConditionReconciled {
			return c.Message
		}
	}
	t.Fatalf("no %s condition was set", ConditionReconciled)
	return ""
}

func TestEmbeddedBTFModeIsReportedOnTheTracerConfigItself(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{BTFMode: podtracev1alpha1.BTFModeEmbedded},
	}
	r := &TracerConfigReconciler{}
	r.setCondition(tc, ConditionReconciled, metav1.ConditionTrue, "Reconciled",
		reconciledMessageFor(tc))

	msg := reconciledMessage(t, tc.Status.Conditions)
	if !strings.Contains(msg, "btfMode=embedded") {
		t.Errorf("Reconciled message = %q, which never mentions the ignored field.\n\n"+
			"The chart ships webhook.enabled=false, so the admission warning reaches "+
			"nobody on a default install. The CR's own status is the only place left "+
			"where kubectl describe shows the author that the knob did nothing.", msg)
	}
	if !strings.Contains(msg, "not implemented") {
		t.Errorf("Reconciled message = %q, which does not say the mode is unimplemented", msg)
	}
}

func TestOtherBTFModesLeaveTheReconciledMessageAlone(t *testing.T) {
	for _, mode := range []podtracev1alpha1.BTFMode{
		"",
		podtracev1alpha1.BTFModeAuto,
		podtracev1alpha1.BTFModeHost,
	} {
		tc := &podtracev1alpha1.TracerConfig{
			Spec: podtracev1alpha1.TracerConfigSpec{BTFMode: mode},
		}
		if msg := reconciledMessageFor(tc); strings.Contains(msg, "btfMode") {
			t.Errorf("btfMode %q produced %q; only the unimplemented mode should be called out",
				mode, msg)
		}
	}
}
