package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestScanPodCgroups_SkipsPodWithNoCgroupDirectory(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "kubepods.slice")
	uidUnder := strings.ReplaceAll(testPodUID, "-", "_")
	resolvable := filepath.Join(root,
		"kubepods-besteffort.slice",
		"kubepods-besteffort-pod"+uidUnder+".slice",
	)
	if err := os.MkdirAll(resolvable, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	withKubepodsRoot(t, root)

	resolved := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "resolved", Namespace: "ns", UID: types.UID(testPodUID)},
		Status:     corev1.PodStatus{QOSClass: corev1.PodQOSBestEffort},
	}
	unresolved := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "unresolved", Namespace: "ns", UID: "no-such-pod-uid"},
		Status:     corev1.PodStatus{QOSClass: corev1.PodQOSBestEffort},
	}

	entries := scanPodCgroups([]*corev1.Pod{resolved, unresolved})
	for _, e := range entries {
		if e.Pod == unresolved {
			t.Fatalf("pod without a cgroup directory must be skipped, got entry %+v", e)
		}
	}
	if len(entries) == 0 {
		t.Fatal("expected at least the resolvable pod's entry")
	}
}

func TestScanPodCgroups_SkipsWhenPodPathIsNotADirectory(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "kubepods.slice")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	uidUnder := strings.ReplaceAll(testPodUID, "-", "_")
	podPathAsFile := filepath.Join(root, "kubepods-pod"+uidUnder+".slice")
	if err := os.WriteFile(podPathAsFile, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	withKubepodsRoot(t, root)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "filepod", Namespace: "ns", UID: types.UID(testPodUID)},
		Status:     corev1.PodStatus{QOSClass: corev1.PodQOSBestEffort},
	}

	entries := scanPodCgroups([]*corev1.Pod{pod})
	for _, e := range entries {
		if e.ContainerName != "" {
			t.Fatalf("no container entries expected when the pod path is a file, got %+v", e)
		}
	}
}
