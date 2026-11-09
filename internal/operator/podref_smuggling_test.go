package operator

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestFilterGrantedPodRefsDropsARefThatSmugglesACrossNamespaceTarget(t *testing.T) {
	scheme, err := NewScheme()
	if err != nil {
		t.Fatalf("scheme: %v", err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(nsObj("victim", nil, false)).Build()
	refs := []podtracev1alpha1.PodRef{
		{Name: "web-0"},
		{Name: "x,victim/db-0"},
		{Namespace: "victim,other", Name: "db-0"},
	}
	allowed, denied, err := filterGrantedPodRefs(context.Background(), c, sourceNS, refs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []podtracev1alpha1.PodRef{{Name: "web-0"}}; !reflect.DeepEqual(allowed, want) {
		t.Errorf("allowed = %v, want %v", allowed, want)
	}
	if len(denied) != 0 {
		t.Errorf("denied = %v, want none", denied)
	}
}

func TestBuildDiagnoseArgsNeverRendersAnInvalidPodRef(t *testing.T) {
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"},
	}
	targets := sessionTargets{PodRefs: []podtracev1alpha1.PodRef{{Name: "web-0"}, {Name: "x,victim/db-0"}}}
	args := buildDiagnoseArgs(s, targets, time.Minute)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "victim") {
		t.Fatalf("args %q carry the smuggled target", joined)
	}
	if !strings.Contains(joined, "--pods team-a/web-0") {
		t.Fatalf("args %q lost the legitimate target", joined)
	}

	onlyInvalid := sessionTargets{PodRefs: []podtracev1alpha1.PodRef{{Name: "x,victim/db-0"}}}
	for _, a := range buildDiagnoseArgs(s, onlyInvalid, time.Minute) {
		if a == "--pods" {
			t.Fatalf("args carry an empty --pods list: %v", buildDiagnoseArgs(s, onlyInvalid, time.Minute))
		}
	}
}
