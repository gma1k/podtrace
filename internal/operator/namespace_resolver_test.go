package operator

import (
	"context"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
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

// grantedNS returns a namespace annotated to allow tracing from the
// given sources ("*" for everyone).
func grantedNS(name string, labels map[string]string, grant string) *corev1.Namespace {
	n := nsObj(name, labels, false)
	n.Annotations = map[string]string{podtracev1alpha1.AllowTracingFromAnnotation: grant}
	return n
}

// sourceNS is the namespace the CR under test lives in.
const sourceNS = "observer"

func TestResolveNamespaceSelector(t *testing.T) {
	cases := []struct {
		name       string
		seedNS     []*corev1.Namespace
		selector   *metav1.LabelSelector
		wantNil    bool
		wantResult []string
		wantDenied []string
		wantErr    bool
	}{
		{
			name:     "NilSelectorReturnsNil",
			selector: nil,
			wantNil:  true,
		},
		{
			name: "EmptySelectorMatchesAllNonTerminatingGranted",
			seedNS: []*corev1.Namespace{
				grantedNS("a", nil, "*"),
				grantedNS("b", map[string]string{"x": "y"}, "*"),
				grantedNS("c", nil, "*"),
			},
			selector:   &metav1.LabelSelector{},
			wantResult: []string{"a", "b", "c"},
			wantDenied: []string{},
		},
		{
			name: "MatchLabelsOnlyMatchesMatching",
			seedNS: []*corev1.Namespace{
				grantedNS("prod-east", map[string]string{"tier": "prod"}, "*"),
				grantedNS("prod-west", map[string]string{"tier": "prod"}, "*"),
				grantedNS("staging", map[string]string{"tier": "staging"}, "*"),
				grantedNS("misc", nil, "*"),
			},
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"tier": "prod"},
			},
			wantResult: []string{"prod-east", "prod-west"},
			wantDenied: []string{},
		},
		{
			name: "MatchExpressionsHonored",
			seedNS: []*corev1.Namespace{
				grantedNS("team-a", map[string]string{"env": "production"}, "*"),
				grantedNS("team-b", map[string]string{"env": "qa"}, "*"),
				grantedNS("team-c", map[string]string{"env": "production"}, "*"),
			},
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"production"}},
				},
			},
			wantResult: []string{"team-a", "team-c"},
			wantDenied: []string{},
		},
		{
			name: "NoMatchesReturnsEmptyNotNil",
			seedNS: []*corev1.Namespace{
				grantedNS("a", map[string]string{"tier": "staging"}, "*"),
			},
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"tier": "prod"},
			},
			wantResult: []string{},
			wantDenied: []string{},
		},
		{
			name: "TerminatingNamespacesExcluded",
			seedNS: []*corev1.Namespace{
				grantedNS("alive", map[string]string{"tier": "prod"}, "*"),
				func() *corev1.Namespace {
					n := grantedNS("dying", map[string]string{"tier": "prod"}, "*")
					ts := metav1.NewTime(time.Now())
					n.DeletionTimestamp = &ts
					n.Finalizers = []string{"kubernetes"}
					return n
				}(),
			},
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"tier": "prod"},
			},
			wantResult: []string{"alive"},
			wantDenied: []string{},
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
				grantedNS("zeta", map[string]string{"x": "y"}, "*"),
				grantedNS("alpha", map[string]string{"x": "y"}, "*"),
				grantedNS("mu", map[string]string{"x": "y"}, "*"),
			},
			selector:   &metav1.LabelSelector{MatchLabels: map[string]string{"x": "y"}},
			wantResult: []string{"alpha", "mu", "zeta"},
			wantDenied: []string{},
		},

		// Tenancy grant filtering — the security boundary. A matched
		// namespace without an AllowTracingFromAnnotation grant for the
		// CR's namespace must land in denied, never in allowed.
		{
			name: "UngrantedMatchesAreDenied",
			seedNS: []*corev1.Namespace{
				nsObj("team-a", map[string]string{"tier": "prod"}, false),
				nsObj("team-b", map[string]string{"tier": "prod"}, false),
			},
			selector:   &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "prod"}},
			wantResult: []string{},
			wantDenied: []string{"team-a", "team-b"},
		},
		{
			name: "ExplicitSourceGrantAllows",
			seedNS: []*corev1.Namespace{
				grantedNS("team-a", map[string]string{"tier": "prod"}, sourceNS),
				grantedNS("team-b", map[string]string{"tier": "prod"}, "someone-else"),
				grantedNS("team-c", map[string]string{"tier": "prod"}, " other , "+sourceNS+" "),
			},
			selector:   &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "prod"}},
			wantResult: []string{"team-a", "team-c"},
			wantDenied: []string{"team-b"},
		},
		{
			name: "OwnNamespaceNeedsNoGrant",
			seedNS: []*corev1.Namespace{
				nsObj(sourceNS, map[string]string{"tier": "prod"}, false),
				nsObj("team-a", map[string]string{"tier": "prod"}, false),
			},
			selector:   &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "prod"}},
			wantResult: []string{sourceNS},
			wantDenied: []string{"team-a"},
		},
		{
			name: "EmptyGrantValueDenies",
			seedNS: []*corev1.Namespace{
				grantedNS("team-a", map[string]string{"tier": "prod"}, ""),
				grantedNS("team-b", map[string]string{"tier": "prod"}, " , "),
			},
			selector:   &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "prod"}},
			wantResult: []string{},
			wantDenied: []string{"team-a", "team-b"},
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

			got, denied, err := ResolveNamespaceSelector(context.Background(), c, tc.selector, sourceNS)
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
				if denied != nil {
					t.Errorf("expected nil denied, got %v", denied)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil slice (possibly empty), got nil")
			}
			if !reflect.DeepEqual(got, tc.wantResult) {
				t.Errorf("allowed: got %v, want %v", got, tc.wantResult)
			}
			if !reflect.DeepEqual(denied, tc.wantDenied) {
				t.Errorf("denied: got %v, want %v", denied, tc.wantDenied)
			}
		})
	}
}

func TestFilterGrantedPodRefs(t *testing.T) {
	ref := func(ns, name string) podtracev1alpha1.PodRef {
		return podtracev1alpha1.PodRef{Namespace: ns, Name: name}
	}
	cases := []struct {
		name        string
		seedNS      []*corev1.Namespace
		refs        []podtracev1alpha1.PodRef
		wantAllowed []podtracev1alpha1.PodRef
		wantDenied  []string
	}{
		{
			name:        "OwnAndImplicitNamespaceAlwaysAllowed",
			refs:        []podtracev1alpha1.PodRef{ref("", "p1"), ref(sourceNS, "p2")},
			wantAllowed: []podtracev1alpha1.PodRef{ref("", "p1"), ref(sourceNS, "p2")},
		},
		{
			name:       "UngrantedCrossNamespaceDenied",
			seedNS:     []*corev1.Namespace{nsObj("team-b", nil, false)},
			refs:       []podtracev1alpha1.PodRef{ref("team-b", "victim")},
			wantDenied: []string{"team-b"},
		},
		{
			name:       "MissingNamespaceDeniedFailClosed",
			refs:       []podtracev1alpha1.PodRef{ref("ghost", "victim")},
			wantDenied: []string{"ghost"},
		},
		{
			name:        "GrantedCrossNamespaceAllowed",
			seedNS:      []*corev1.Namespace{grantedNS("team-b", nil, sourceNS)},
			refs:        []podtracev1alpha1.PodRef{ref("team-b", "pod-a"), ref("team-b", "pod-b")},
			wantAllowed: []podtracev1alpha1.PodRef{ref("team-b", "pod-a"), ref("team-b", "pod-b")},
		},
		{
			name: "MixedRefsSplitCorrectly",
			seedNS: []*corev1.Namespace{
				grantedNS("granted", nil, "*"),
				nsObj("refused", nil, false),
			},
			refs: []podtracev1alpha1.PodRef{
				ref("", "own"),
				ref("granted", "ok"),
				ref("refused", "no-1"),
				ref("refused", "no-2"),
			},
			wantAllowed: []podtracev1alpha1.PodRef{ref("", "own"), ref("granted", "ok")},
			wantDenied:  []string{"refused"},
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

			allowed, denied, err := filterGrantedPodRefs(context.Background(), c, sourceNS, tc.refs)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(allowed, tc.wantAllowed) {
				t.Errorf("allowed: got %v, want %v", allowed, tc.wantAllowed)
			}
			if !reflect.DeepEqual(denied, tc.wantDenied) {
				t.Errorf("denied: got %v, want %v", denied, tc.wantDenied)
			}
		})
	}
}
