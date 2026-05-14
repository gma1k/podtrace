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

// Tests for cgroupPathForPod against synthetic /sys/fs/cgroup trees.
//
// Each subtest builds a temp directory mimicking one kubelet cgroup
// layout, then asserts cgroupPathForPod returns the right per-pod
// directory. The tests bypass discoverKubepodsRoot entirely so they do
// not depend on the host's actual cgroup configuration — they pass
// equally on macOS dev machines and Linux CI.

const testPodUID = "abcd1234-ef56-7890-cdef-1234567890ab"

func newTestPod(qos corev1.PodQOSClass) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID(testPodUID)},
		Status:     corev1.PodStatus{QOSClass: qos},
	}
}

// TestCgroupPathForPod_SystemdKubepodsSlice covers the standard
// systemd-driver layout used by most managed Kubernetes distributions
// (RHEL/Fedora bare metal, GKE, etc.).
func TestCgroupPathForPod_SystemdKubepodsSlice(t *testing.T) {
	root := t.TempDir()
	uidUnder := strings.ReplaceAll(testPodUID, "-", "_")

	cases := []struct {
		name      string
		qos       corev1.PodQOSClass
		makePath  string
		expectSeg string
	}{
		{
			name:      "Besteffort",
			qos:       corev1.PodQOSBestEffort,
			makePath:  filepath.Join("kubepods-besteffort.slice", "kubepods-besteffort-pod"+uidUnder+".slice"),
			expectSeg: "kubepods-besteffort-pod" + uidUnder + ".slice",
		},
		{
			name:      "Burstable",
			qos:       corev1.PodQOSBurstable,
			makePath:  filepath.Join("kubepods-burstable.slice", "kubepods-burstable-pod"+uidUnder+".slice"),
			expectSeg: "kubepods-burstable-pod" + uidUnder + ".slice",
		},
		{
			name:      "Guaranteed", // no QOS sub-slice
			qos:       corev1.PodQOSGuaranteed,
			makePath:  "kubepods-pod" + uidUnder + ".slice",
			expectSeg: "kubepods-pod" + uidUnder + ".slice",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subroot := filepath.Join(root, tc.name, "kubepods.slice")
			if err := os.MkdirAll(filepath.Join(subroot, tc.makePath), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			got := cgroupPathForPod(newTestPod(tc.qos), subroot)
			if !strings.HasSuffix(got, tc.expectSeg) {
				t.Errorf("got %q, want suffix %q", got, tc.expectSeg)
			}
		})
	}
}

// TestCgroupPathForPod_KubeletSliceParent covers the layout where the
// kubelet runs as a systemd unit inside its own slice (kind, k3s, k0s,
// MicroShift, some Talos profiles). Every slice level prefixes with
// "kubelet-".
func TestCgroupPathForPod_KubeletSliceParent(t *testing.T) {
	root := t.TempDir()
	uidUnder := strings.ReplaceAll(testPodUID, "-", "_")
	subroot := filepath.Join(root, "kubelet.slice", "kubelet-kubepods.slice")
	if err := os.MkdirAll(filepath.Join(subroot,
		"kubelet-kubepods-besteffort.slice",
		"kubelet-kubepods-besteffort-pod"+uidUnder+".slice",
	), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	got := cgroupPathForPod(newTestPod(corev1.PodQOSBestEffort), subroot)
	want := "kubelet-kubepods-besteffort-pod" + uidUnder + ".slice"
	if !strings.HasSuffix(got, want) {
		t.Errorf("got %q, want suffix %q", got, want)
	}
}

// TestCgroupPathForPod_CgroupfsDriver covers the legacy cgroupfs
// driver layout (older Debian, some embedded distros). UID separator
// remains '-' here because cgroupfs does not impose systemd's slice
// syntax.
func TestCgroupPathForPod_CgroupfsDriver(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name     string
		qos      corev1.PodQOSClass
		makePath string
	}{
		{"Besteffort", corev1.PodQOSBestEffort, filepath.Join("besteffort", "pod"+testPodUID)},
		{"Guaranteed", corev1.PodQOSGuaranteed, "pod" + testPodUID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subroot := filepath.Join(root, tc.name, "kubepods")
			if err := os.MkdirAll(filepath.Join(subroot, tc.makePath), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			got := cgroupPathForPod(newTestPod(tc.qos), subroot)
			want := filepath.Join(subroot, tc.makePath)
			if got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

// TestCgroupPathForPod_EmptyRoot ensures empty-root callers (i.e.
// discovery returned nothing) get an empty path back rather than a
// path that happens to stat-fail.
func TestCgroupPathForPod_EmptyRoot(t *testing.T) {
	if got := cgroupPathForPod(newTestPod(corev1.PodQOSBestEffort), ""); got != "" {
		t.Errorf("empty root must yield empty path, got %q", got)
	}
}

func TestResolveCgroupIDs_IncludesContainerScopes(t *testing.T) {
	root := t.TempDir()
	uidUnder := strings.ReplaceAll(testPodUID, "-", "_")
	podSlice := filepath.Join(root, "kubepods.slice",
		"kubepods-besteffort.slice",
		"kubepods-besteffort-pod"+uidUnder+".slice",
	)
	containers := []string{
		"cri-containerd-abc123.scope",
		"cri-containerd-def456.scope",
	}
	for _, c := range containers {
		if err := os.MkdirAll(filepath.Join(podSlice, c), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	staged := []string{podSlice}
	for _, c := range containers {
		staged = append(staged, filepath.Join(podSlice, c))
	}
	got := map[uint64]struct{}{}
	for _, p := range staged {
		id, err := cgroupIDFromPath(p)
		if err != nil {
			t.Fatalf("cgroupIDFromPath(%q): %v", p, err)
		}
		got[id] = struct{}{}
	}
	if len(got) != 3 {
		t.Errorf("staged %d directories, got %d distinct inodes (pod + 2 containers)", 3, len(got))
	}
}

// TestCgroupPathForPod_QOSDefaultsToBestEffort handles the edge case
// where a Pod has not yet received its PodStatus from the kubelet
// (status.qosClass is empty); the resolver picks besteffort as the
// most permissive guess.
func TestCgroupPathForPod_QOSDefaultsToBestEffort(t *testing.T) {
	root := t.TempDir()
	uidUnder := strings.ReplaceAll(testPodUID, "-", "_")
	subroot := filepath.Join(root, "kubepods.slice")
	if err := os.MkdirAll(filepath.Join(subroot,
		"kubepods-besteffort.slice",
		"kubepods-besteffort-pod"+uidUnder+".slice",
	), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pod := newTestPod("") // empty QOS
	got := cgroupPathForPod(pod, subroot)
	if !strings.Contains(got, "besteffort") {
		t.Errorf("empty QOS should fall back to besteffort; got %q", got)
	}
}
