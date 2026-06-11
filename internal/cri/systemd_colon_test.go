package cri

import "testing"

// TestExpandSystemdColonPath: the CRI reports the systemd cgroup driver's
// colon form on GKE/EKS/kubeadm defaults; without expansion the path never
// matched the filesystem and CRI resolution silently failed for every pod.
func TestExpandSystemdColonPath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "containerd colon form",
			in:   "kubepods-burstable-pod2c48a299_e1f2.slice:cri-containerd:0123abc",
			want: "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod2c48a299_e1f2.slice/cri-containerd-0123abc.scope",
		},
		{
			name: "crio colon form",
			in:   "kubepods-besteffort-podabc.slice:crio:fff",
			want: "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc.slice/crio-fff.scope",
		},
		{
			name: "plain path untouched",
			in:   "/kubepods/burstable/pod123/abc",
			want: "/kubepods/burstable/pod123/abc",
		},
		{
			name: "non-slice colon form untouched",
			in:   "notaslice:cri-containerd:abc",
			want: "notaslice:cri-containerd:abc",
		},
		{
			name: "missing id untouched",
			in:   "kubepods.slice:cri-containerd:",
			want: "kubepods.slice:cri-containerd:",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := expandSystemdColonPath(c.in); got != c.want {
				t.Errorf("expandSystemdColonPath(%q) =\n  %q, want\n  %q", c.in, got, c.want)
			}
		})
	}
}

func TestExpandSystemdSlice(t *testing.T) {
	if got := expandSystemdSlice("kubepods.slice"); got != "kubepods.slice" {
		t.Errorf("single segment = %q", got)
	}
	want := "a.slice/a-b.slice/a-b-c.slice"
	if got := expandSystemdSlice("a-b-c.slice"); got != want {
		t.Errorf("nested = %q, want %q", got, want)
	}
}
