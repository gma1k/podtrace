package operator

import (
	"context"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func nsObj(name string, labels map[string]string, terminating bool) *corev1.Namespace {
	n := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
	if terminating {
		t := metav1.NewTime(time.Now())
		n.DeletionTimestamp = &t
		n.Finalizers = []string{"kubernetes"}
	}
	return n
}

func TestResolveNamespaceSelector(t *testing.T) {
	cases := []struct {
		name       string
		seedNS     []*corev1.Namespace
		selector   *metav1.LabelSelector
		wantNil    bool
		wantResult []string
		wantErr    bool
	}{
		{
			name:    "NilSelectorReturnsNil",
			selector: nil,
			wantNil:  true,
		},
		{
			name: "EmptySelectorMatchesAllNonTerminating",
			seedNS: []*corev1.Namespace{
				nsObj("a", nil, false),
				nsObj("b", map[string]string{"x": "y"}, false),
				nsObj("c", nil, true),
			},
			selector:   &metav1.LabelSelector{},
			wantResult: []string{"a", "b"},
		},
		{
			name: "MatchLabelsOnlyMatchesMatching",
			seedNS: []*corev1.Namespace{
				nsObj("prod-east", map[string]string{"tier": "prod"}, false),
				nsObj("prod-west", map[string]string{"tier": "prod"}, false),
				nsObj("staging", map[string]string{"tier": "staging"}, false),
				nsObj("misc", nil, false),
			},
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"tier": "prod"},
			},
			wantResult: []string{"prod-east", "prod-west"},
		},
		{
			name: "MatchExpressionsHonored",
			seedNS: []*corev1.Namespace{
				nsObj("team-a", map[string]string{"env": "production"}, false),
				nsObj("team-b", map[string]string{"env": "qa"}, false),
				nsObj("team-c", map[string]string{"env": "production"}, false),
			},
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"production"}},
				},
			},
			wantResult: []string{"team-a", "team-c"},
		},
		{
			name: "NoMatchesReturnsEmptyNotNil",
			seedNS: []*corev1.Namespace{
				nsObj("a", map[string]string{"tier": "staging"}, false),
			},
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"tier": "prod"},
			},
			wantResult: []string{},
		},
		{
			name: "TerminatingNamespacesExcluded",
			seedNS: []*corev1.Namespace{
				nsObj("alive", map[string]string{"tier": "prod"}, false),
				nsObj("dying", map[string]string{"tier": "prod"}, true),
			},
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"tier": "prod"},
			},
			wantResult: []string{"alive"},
		},
		{
			name: "MalformedSelectorReturnsError",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "k", Operator: "BogusOp", Values: []string{"v"}},
				},
			},
			wantErr: true,
		},
		{
			name: "OutputAlwaysSorted",
			seedNS: []*corev1.Namespace{
				nsObj("zeta", map[string]string{"x": "y"}, false),
				nsObj("alpha", map[string]string{"x": "y"}, false),
				nsObj("mu", map[string]string{"x": "y"}, false),
			},
			selector:   &metav1.LabelSelector{MatchLabels: map[string]string{"x": "y"}},
			wantResult: []string{"alpha", "mu", "zeta"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scheme, err := NewScheme()
			if err != nil {
				t.Fatalf("scheme: %v", err)
			}
			builder := fake.NewClientBuilder().WithScheme(scheme)
			for _, ns := range tc.seedNS {
				builder = builder.WithObjects(ns)
			}
			c := builder.Build()

			got, err := ResolveNamespaceSelector(context.Background(), c, tc.selector)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantNil {
				if got != nil {
					t.Errorf("expected nil result, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil slice (possibly empty), got nil")
			}
			if !reflect.DeepEqual(got, tc.wantResult) {
				t.Errorf("got %v, want %v", got, tc.wantResult)
			}
		})
	}
}