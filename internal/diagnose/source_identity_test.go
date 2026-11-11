package diagnose

import "testing"

func TestADiagnosticianNamesThePodItDiagnoses(t *testing.T) {
	d := NewDiagnosticianWithK8sAndThresholds("checkout-7d9f", "shop", 10, 100, 10)
	if d.SourcePod() != "checkout-7d9f" || d.SourceNamespace() != "shop" {
		t.Errorf("source = %q/%q, want checkout-7d9f/shop", d.SourcePod(), d.SourceNamespace())
	}
	if d := NewDiagnostician(); d.SourcePod() != "" || d.SourceNamespace() != "" {
		t.Errorf("source = %q/%q for a diagnostician without a pod", d.SourcePod(), d.SourceNamespace())
	}
}
