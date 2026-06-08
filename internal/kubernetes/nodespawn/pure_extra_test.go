package nodespawn

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestIndexAfterScheme(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"containerd", "containerd://abc123", len("containerd://")},
		{"docker", "docker://deadbeef", len("docker://")},
		{"no scheme", "abc123", -1},
		{"empty", "", -1},
		{"only scheme delimiter at end", "x://", len("x://")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := indexAfterScheme(tt.in); got != tt.want {
				t.Errorf("indexAfterScheme(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestTolerationKey(t *testing.T) {
	sec := int64(30)
	withSeconds := corev1.Toleration{
		Key:               "node.kubernetes.io/unreachable",
		Operator:          corev1.TolerationOpExists,
		Effect:            corev1.TaintEffectNoExecute,
		TolerationSeconds: &sec,
	}
	withoutSeconds := corev1.Toleration{
		Key:      "dedicated",
		Operator: corev1.TolerationOpEqual,
		Value:    "gpu",
		Effect:   corev1.TaintEffectNoSchedule,
	}

	keyWith := tolerationKey(withSeconds)
	keyWithout := tolerationKey(withoutSeconds)

	if keyWith == keyWithout {
		t.Fatalf("distinct tolerations produced identical keys: %q", keyWith)
	}
	// TolerationSeconds value must appear in the key when set.
	if want := "|30"; keyWith[len(keyWith)-len(want):] != want {
		t.Errorf("key %q should end with the seconds value %q", keyWith, want)
	}
	// Nil TolerationSeconds renders as "nil".
	if want := "|nil"; keyWithout[len(keyWithout)-len(want):] != want {
		t.Errorf("key %q should end with %q for nil seconds", keyWithout, want)
	}

	// Same toleration must hash to the same key (stable dedupe).
	if tolerationKey(withoutSeconds) != keyWithout {
		t.Error("tolerationKey is not deterministic")
	}
}
