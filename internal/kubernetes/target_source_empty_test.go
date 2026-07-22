package kubernetes_test

import (
	"testing"

	"github.com/podtrace/podtrace/internal/kubernetes"
)

func TestToTracerTargets_EmptyInputReturnsNil(t *testing.T) {
	if out := kubernetes.ToTracerTargets(nil); out != nil {
		t.Errorf("ToTracerTargets(nil) = %v, want nil", out)
	}
	if out := kubernetes.ToTracerTargets([]*kubernetes.PodInfo{}); out != nil {
		t.Errorf("ToTracerTargets(empty) = %v, want nil", out)
	}
}
