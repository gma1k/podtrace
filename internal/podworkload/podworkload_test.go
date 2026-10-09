package podworkload

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestResolveWorkload(t *testing.T) {
	tcontroller := true
	notController := false

	cases := []struct {
		name     string
		pod      *corev1.Pod
		wantKind string
		wantName string
	}{
		{
			name: "no owners → orphan pod degrades to Pod",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "lonely"},
			},
			wantKind: "Pod",
			wantName: "lonely",
		},
		{
			name: "owner ref present but not controller → orphan",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "free-pod",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "ReplicaSet", Name: "rs-7d8c9c", Controller: &notController},
					},
				},
			},
			wantKind: "Pod",
			wantName: "free-pod",
		},
		{
			name: "ReplicaSet with valid hash suffix rolls up to Deployment",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "p-1",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "ReplicaSet", Name: "shopping-cart-7d8c9c", Controller: &tcontroller},
					},
				},
			},
			wantKind: "Deployment",
			wantName: "shopping-cart",
		},
		{
			name: "ReplicaSet without recognisable hash → no rollup",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "p-2",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "ReplicaSet", Name: "rs-without-hash", Controller: &tcontroller},
					},
				},
			},
			wantKind: "ReplicaSet",
			wantName: "rs-without-hash",
		},
		{
			name: "StatefulSet → reported as-is",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "StatefulSet", Name: "kafka", Controller: &tcontroller},
					},
				},
			},
			wantKind: "StatefulSet",
			wantName: "kafka",
		},
		{
			name: "DaemonSet → reported as-is",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "DaemonSet", Name: "fluentd", Controller: &tcontroller},
					},
				},
			},
			wantKind: "DaemonSet",
			wantName: "fluentd",
		},
		{
			name: "Job → reported as-is",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "Job", Name: "nightly-backup-29543", Controller: &tcontroller},
					},
				},
			},
			wantKind: "Job",
			wantName: "nightly-backup-29543",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, name := Of(tc.pod)
			if kind != tc.wantKind || name != tc.wantName {
				t.Errorf("resolveWorkload = (%q, %q), want (%q, %q)",
					kind, name, tc.wantKind, tc.wantName)
			}
		})
	}
}

func TestDeploymentFromReplicaSet(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"shopping-cart-7d8c9c", "shopping-cart", true},
		{"webapp-58b6f7c9d4", "webapp", true},
		{"a-bcdfg", "a", true},
		{"single", "", false},
		{"trailing-", "", false},
		{"my-rs-prod", "", false},
		{"deploy-toolong-suffixabcdefgh", "", false},
		{"deploy-9c", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := DeploymentFromReplicaSet(tc.in)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("DeploymentFromReplicaSet(%q) = (%q, %v), want (%q, %v)",
					tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestDeploymentNameSurvivesEveryPodTemplateHashCharacter(t *testing.T) {
	for _, chunk := range []string{
		"0123456789",
		"bcdfghjkmn",
		"pqrstvwxyz",
		"jkmn7",
		"pqrst",
		"vwxyz",
	} {
		name, ok := DeploymentFromReplicaSet("checkout-" + chunk)
		if !ok || name != "checkout" {
			t.Errorf("DeploymentFromReplicaSet(checkout-%s) = %q, %v; want checkout, true. "+
				"kube-controller-manager mints the suffix from this alphabet, and a character "+
				"it rejects leaves the workload labelled by ReplicaSet, which changes on every "+
				"rollout and breaks continuity of every series keyed on workload", chunk, name, ok)
		}
	}
}

func TestAReplicaSetSuffixOutsideTheAlphabetIsNotAHash(t *testing.T) {
	for _, suffix := range []string{"aeiou", "ABCDE", "12-45", "abc", strings.Repeat("b", 13)} {
		if name, ok := DeploymentFromReplicaSet("checkout-" + suffix); ok {
			t.Errorf("DeploymentFromReplicaSet(checkout-%s) = %q, true; want false. A name that "+
				"merely contains a dash is not a ReplicaSet suffix, and trimming it would "+
				"report a workload that does not exist", suffix, name)
		}
	}
}
