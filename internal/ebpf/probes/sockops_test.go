package probes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/config"
)

func TestKubepodsRootPrefersTheFirstCandidateThatExists(t *testing.T) {
	base := t.TempDir()
	for _, c := range []string{"kubepods", "kubelet.slice/kubelet-kubepods.slice"} {
		if err := os.MkdirAll(filepath.Join(base, c), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	got := kubepodsRootUnder(base)
	if want := filepath.Join(base, "kubepods"); got != want {
		t.Errorf("kubepodsRootUnder = %q, want %q; candidate order decides which cgroup "+
			"the sock_ops hook covers", got, want)
	}
}

func TestKubepodsRootFindsEveryKnownLayout(t *testing.T) {
	for _, candidate := range kubepodsRootCandidates {
		t.Run(candidate, func(t *testing.T) {
			base := t.TempDir()
			if err := os.MkdirAll(filepath.Join(base, candidate), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if got, want := kubepodsRootUnder(base), filepath.Join(base, candidate); got != want {
				t.Errorf("kubepodsRootUnder = %q, want %q", got, want)
			}
		})
	}
}

func TestKubepodsRootIsEmptyOutsideKubernetes(t *testing.T) {
	if got := kubepodsRootUnder(t.TempDir()); got != "" {
		t.Errorf("kubepodsRootUnder = %q on a node with no kubelet slices, want empty", got)
	}
	if got := kubepodsRootUnder(""); got != "" {
		t.Errorf("kubepodsRootUnder(\"\") = %q, want empty", got)
	}
}

func TestKubepodsRootResolvesUnderTheConfiguredCgroupMount(t *testing.T) {
	if !filepath.IsAbs(config.CgroupBasePath) {
		t.Fatalf("CgroupBasePath is not absolute: %q", config.CgroupBasePath)
	}
	if got := KubepodsRoot(); got != "" && !filepath.IsAbs(got) {
		t.Errorf("KubepodsRoot returned a relative path %q", got)
	}
}

func TestAttachSockOpsProbesDoesNothingWhileDisabled(t *testing.T) {
	if config.SockOpsRTTEnabled {
		t.Skip("PODTRACE_SOCKOPS_RTT_ENABLED is on in this environment")
	}
	if got := AttachSockOpsProbes(&ebpf.Collection{}, []string{"/sys/fs/cgroup"}); got != nil {
		t.Errorf("attached %d links while the hook is switched off; it costs a callback "+
			"on roughly every ACK, so turning it off must actually detach it", len(got))
	}
}

func TestSockOpsEnabledTracksItsConfigFlag(t *testing.T) {
	if got, want := SockOpsEnabled(), config.SockOpsRTTEnabled; got != want {
		t.Errorf("SockOpsEnabled() = %v, config says %v", got, want)
	}
}

func TestAttachSockOpsProbesReturnsNothingWithoutTheProgram(t *testing.T) {
	restore := config.SockOpsRTTEnabled
	config.SockOpsRTTEnabled = true
	defer func() { config.SockOpsRTTEnabled = restore }()

	if got := AttachSockOpsProbes(&ebpf.Collection{}, []string{"/sys/fs/cgroup"}); got != nil {
		t.Errorf("attached %d links from a collection with no sockops_rtt program", len(got))
	}
}

func TestSockOpsCgroupsDropsBlanksAndDuplicates(t *testing.T) {
	got := sockOpsCgroupsWith([]string{"", "/a", "/a", "/b", ""}, "/kubepods")
	want := []string{"/a", "/b"}
	if len(got) != len(want) {
		t.Fatalf("sockOpsCgroups = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d = %q, want %q; attaching the same cgroup twice would "+
				"double every RTT sample from it", i, got[i], want[i])
		}
	}
}

func TestSockOpsCgroupsFallsBackToTheKubepodsRootWhenNoTargetsExist(t *testing.T) {
	got := sockOpsCgroupsWith(nil, "/sys/fs/cgroup/kubepods.slice")
	if len(got) != 1 || got[0] != "/sys/fs/cgroup/kubepods.slice" {
		t.Errorf("sockOpsCgroupsWith = %v, want the kubepods root.\n\nThe continuous plane "+
			"sets no target cgroups, so without this fallback the hook attaches to nothing "+
			"in the only mode it exists for.", got)
	}
}

func TestSockOpsCgroupsAttachesNowhereOffKubernetes(t *testing.T) {
	if got := sockOpsCgroupsWith(nil, ""); got != nil {
		t.Errorf("sockOpsCgroupsWith = %v with no targets and no kubepods root, want nil", got)
	}
}

func TestSockOpsCgroupsPrefersExplicitTargetsOverTheRoot(t *testing.T) {
	got := sockOpsCgroupsWith([]string{"/pod-a", "/pod-b"}, "/kubepods")
	if len(got) != 2 || got[0] != "/pod-a" || got[1] != "/pod-b" {
		t.Errorf("sockOpsCgroups = %v, want the caller's targets; a session narrows the "+
			"hook to its own pods and must not widen to the whole node", got)
	}
}

func TestSockOpsCgroupsTreatsAnAllBlankListAsEmpty(t *testing.T) {
	if got := sockOpsCgroupsWith([]string{"", ""}, "/kubepods"); len(got) != 1 || got[0] != "/kubepods" {
		t.Errorf("sockOpsCgroupsWith = %v, want the fallback; a list of blanks is no list", got)
	}
}

func TestSockOpsCgroupsUsesTheRealRootByDefault(t *testing.T) {
	if got, want := sockOpsCgroups(nil), sockOpsCgroupsWith(nil, KubepodsRoot()); len(got) != len(want) {
		t.Errorf("sockOpsCgroups = %v, sockOpsCgroupsWith(KubepodsRoot()) = %v", got, want)
	}
}

func TestSockOpsCgroupsDropsCgroupsNestedInsideOthers(t *testing.T) {
	pod := "/sys/fs/cgroup/kubepods.slice/pod-abc.slice"
	container := pod + "/cri-containerd-def.scope"

	got := sockOpsCgroupsWith([]string{pod, container}, "/kubepods")
	if len(got) != 1 || got[0] != pod {
		t.Errorf("sockOpsCgroupsWith = %v, want just the pod slice.\n\nA bpf_link attaches "+
			"in multi mode, so attaching to both a pod slice and its container scope runs "+
			"the program twice per socket and counts every RTT sample twice.", got)
	}
}

func TestSockOpsCgroupsKeepsSiblingCgroups(t *testing.T) {
	a := "/sys/fs/cgroup/kubepods.slice/pod-a.slice"
	b := "/sys/fs/cgroup/kubepods.slice/pod-b.slice"

	if got := sockOpsCgroupsWith([]string{a, b}, "/kubepods"); len(got) != 2 {
		t.Errorf("sockOpsCgroupsWith = %v, want both siblings; neither contains the other", got)
	}
}

func TestSockOpsCgroupsDoesNotTreatASharedPrefixAsNesting(t *testing.T) {
	a := "/sys/fs/cgroup/kubepods.slice/pod-ab"
	b := "/sys/fs/cgroup/kubepods.slice/pod-a"

	got := sockOpsCgroupsWith([]string{a, b}, "/kubepods")
	if len(got) != 2 {
		t.Errorf("sockOpsCgroupsWith = %v, want both; pod-ab is not inside pod-a and a "+
			"plain string prefix test would wrongly drop it", got)
	}
}

func TestSockOpsCgroupsCollapsesADeepChain(t *testing.T) {
	root := "/sys/fs/cgroup/kubepods.slice"
	mid := root + "/pod.slice"
	leaf := mid + "/container.scope"

	got := sockOpsCgroupsWith([]string{leaf, mid, root}, "/kubepods")
	if len(got) != 1 || got[0] != root {
		t.Errorf("sockOpsCgroupsWith = %v, want only the outermost cgroup", got)
	}
}

func TestACgroupIsNotItsOwnDescendant(t *testing.T) {
	p := "/sys/fs/cgroup/kubepods.slice/pod-a.slice"
	if isCgroupDescendant(p, p) {
		t.Error("a cgroup was treated as nested inside itself, which would drop every " +
			"path from the attach set")
	}
}

func TestNothingIsADescendantOfAnEmptyAncestor(t *testing.T) {
	if isCgroupDescendant("/sys/fs/cgroup/kubepods.slice", "") {
		t.Error("an empty ancestor matched; an empty string prefixes every path")
	}
}

func TestADescendantIsRecognisedWithOrWithoutATrailingSlash(t *testing.T) {
	child := "/sys/fs/cgroup/kubepods.slice/pod-a.slice"
	for _, ancestor := range []string{"/sys/fs/cgroup/kubepods.slice", "/sys/fs/cgroup/kubepods.slice/"} {
		if !isCgroupDescendant(child, ancestor) {
			t.Errorf("%q not recognised as inside %q", child, ancestor)
		}
	}
}
