package v1alpha1

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestValidateTargetShapes(t *testing.T) {
	badExpr := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Bogus", Values: []string{"x"}}}}
	inWithoutValues := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpIn}}}
	good := metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}}
	cases := []struct {
		name    string
		sel     *metav1.LabelSelector
		refs    []podtracev1alpha1.PodRef
		app     *podtracev1alpha1.AppSelector
		wantErr string
	}{
		{"all unset", nil, nil, nil, ""},
		{"good selector", &good, nil, nil, ""},
		{"bad selector operator", &badExpr, nil, nil, "spec.selector"},
		{"In without values", &inWithoutValues, nil, nil, "spec.selector"},
		{"good appSelector", nil, nil, &podtracev1alpha1.AppSelector{MatchSelectors: []metav1.LabelSelector{good}}, ""},
		{"bad appSelector entry", nil, nil, &podtracev1alpha1.AppSelector{MatchSelectors: []metav1.LabelSelector{good, badExpr}}, "spec.appSelector.matchSelectors[1]"},
		{"good podRefs", nil, []podtracev1alpha1.PodRef{{Name: "etcd-node.ec2.internal"}}, nil, ""},
		{"comma podRef", nil, []podtracev1alpha1.PodRef{{Name: "a"}, {Name: "x,victim/db"}}, nil, "spec.podRefs[1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTargetShapes(tc.sel, tc.refs, tc.app)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestPodTraceWebhookRejectsAMalformedSelector(t *testing.T) {
	v := &PodTraceCustomValidator{Client: entitlementClient(t, fleetBTracerConfig())}
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "team-a"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Bogus"}}},
		},
	}
	_, err := v.ValidateCreate(context.Background(), pt)
	if err == nil || !strings.Contains(err.Error(), "spec.selector") {
		t.Fatalf("err = %v, want a spec.selector rejection", err)
	}
}

func TestPodTraceWebhookRejectsAMalformedAppSelector(t *testing.T) {
	v := &PodTraceCustomValidator{Client: entitlementClient(t, fleetBTracerConfig())}
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "team-a"},
		Spec: podtracev1alpha1.PodTraceSpec{
			AppSelector: &podtracev1alpha1.AppSelector{MatchSelectors: []metav1.LabelSelector{
				{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpExists, Values: []string{"x"}}}},
			}},
		},
	}
	_, err := v.ValidateCreate(context.Background(), pt)
	if err == nil || !strings.Contains(err.Error(), "spec.appSelector.matchSelectors[0]") {
		t.Fatalf("err = %v, want a spec.appSelector rejection", err)
	}
}

func TestSessionWebhookRejectsACommaBearingPodRef(t *testing.T) {
	v := &PodTraceSessionCustomValidator{Client: entitlementClient(t, fleetBTracerConfig())}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			PodRefs:  []podtracev1alpha1.PodRef{{Name: "web-0"}, {Name: "x,victim/db-0"}},
			Duration: metav1.Duration{Duration: 30 * time.Second},
		},
	}
	_, err := v.ValidateCreate(context.Background(), s)
	if err == nil || !strings.Contains(err.Error(), "spec.podRefs[1]") {
		t.Fatalf("err = %v, want a spec.podRefs[1] rejection", err)
	}
}

func TestScheduleWebhookRejectsACommaBearingTemplatePodRef(t *testing.T) {
	v := &PodTraceScheduleCustomValidator{Client: entitlementClient(t, fleetBTracerConfig()), SystemNamespace: "podtrace-system"}
	sch := reportOnlySchedule("nightly")
	sch.Spec.SessionTemplate.Spec.Selector = nil
	sch.Spec.SessionTemplate.Spec.PodRefs = []podtracev1alpha1.PodRef{{Name: "x,victim/db-0"}}
	_, err := v.validate(context.Background(), sch)
	if err == nil || !strings.Contains(err.Error(), "spec.sessionTemplate.spec.podRefs[0]") {
		t.Fatalf("err = %v, want a template podRefs rejection", err)
	}
}
