package nodespawn

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func spawnPod(t *testing.T, btfFile string) *corev1.Pod {
	t.Helper()
	pod, err := BuildPodSpec(PodSpecOptions{
		NodeName:  "node-a",
		Namespace: "app",
		Image:     "ghcr.io/gma1k/podtrace:dev",
		Args:      []string{"--help"},
		BTFFile:   btfFile,
	})
	if err != nil {
		t.Fatalf("BuildPodSpec: %v", err)
	}
	return pod
}

func spawnEnv(pod *corev1.Pod, name string) (string, bool) {
	for _, c := range pod.Spec.Containers {
		for _, e := range c.Env {
			if e.Name == name {
				return e.Value, true
			}
		}
	}
	return "", false
}

func spawnVolume(pod *corev1.Pod, name string) (corev1.Volume, bool) {
	for _, v := range pod.Spec.Volumes {
		if v.Name == name {
			return v, true
		}
	}
	return corev1.Volume{}, false
}

func TestASuppliedBTFFileIsMountedIntoTheSpawnedPod(t *testing.T) {
	pod := spawnPod(t, "/var/lib/podtrace/vmlinux.btf")

	got, ok := spawnEnv(pod, "PODTRACE_BTF_FILE")
	if !ok || got != "/etc/podtrace/btf/vmlinux.btf" {
		t.Errorf("PODTRACE_BTF_FILE = %q (set=%v), want the blob under the mount dir.\n\n"+
			"The CLI spawns a pod that loads its own BPF collection. Without this, "+
			"btfMode=file fixes the agent and sessions while the CLI stays broken on "+
			"exactly the node the mode exists for.", got, ok)
	}

	vol, ok := spawnVolume(pod, "btf-file")
	if !ok || vol.HostPath == nil {
		t.Fatalf("no hostPath btf-file volume: %+v", vol)
	}
	if vol.HostPath.Path != "/var/lib/podtrace/vmlinux.btf" {
		t.Errorf("hostPath = %q, want the supplied path", vol.HostPath.Path)
	}
	if vol.HostPath.Type == nil || *vol.HostPath.Type != corev1.HostPathFile {
		t.Errorf("hostPath type = %v, want File; mounting the directory would expose "+
			"whatever else sits beside the blob to a privileged pod", vol.HostPath.Type)
	}

	mounted := false
	for _, c := range pod.Spec.Containers {
		for _, m := range c.VolumeMounts {
			if m.Name == "btf-file" {
				mounted = true
				if !m.ReadOnly {
					t.Error("the blob is mounted writable")
				}
				if m.MountPath != "/etc/podtrace/btf/vmlinux.btf" {
					t.Errorf("mountPath = %q, want the path the env var names", m.MountPath)
				}
			}
		}
	}
	if !mounted {
		t.Error("no btf-file mount; the env var points at a path that does not exist")
	}
}

func TestNoBTFFileLeavesTheSpawnedPodAlone(t *testing.T) {
	pod := spawnPod(t, "")

	if got, ok := spawnEnv(pod, "PODTRACE_BTF_FILE"); ok {
		t.Errorf("PODTRACE_BTF_FILE = %q was set without --btf-file.\n\nAn unset flag must "+
			"leave the pod resolving host BTF, which is what nearly every node needs", got)
	}
	if _, ok := spawnVolume(pod, "btf-file"); ok {
		t.Error("a btf-file volume was rendered without --btf-file")
	}
}

func TestTheSpawnedPodAndTheAgentAgreeOnTheMountPath(t *testing.T) {
	pod := spawnPod(t, "/some/where/else/node.btf")

	got, _ := spawnEnv(pod, "PODTRACE_BTF_FILE")
	if got != "/etc/podtrace/btf/node.btf" {
		t.Errorf("PODTRACE_BTF_FILE = %q; the CLI and the agent DaemonSet must mount under "+
			"the same directory or a report reading one path and an agent reading another "+
			"become impossible to compare", got)
	}
}
