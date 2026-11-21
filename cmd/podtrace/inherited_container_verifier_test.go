package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/gma1k/podtrace/internal/ebpf"
	tracerpkg "github.com/gma1k/podtrace/internal/ebpf/tracer"
	"github.com/gma1k/podtrace/internal/kubernetes"
)

const (
	selectedID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	siblingID  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	debugID    = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	unknownID  = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

type staticParents struct {
	namespace, pod, path string
	parent               uint64
}

func (s staticParents) parentTarget(parent uint64) (string, string, string, bool) {
	if parent != s.parent {
		return "", "", "", false
	}
	return s.namespace, s.pod, s.path, true
}

func verifierPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", ContainerID: "containerd://" + selectedID},
				{Name: "sidecar", ContainerID: "containerd://" + siblingID},
			},
			EphemeralContainerStatuses: []corev1.ContainerStatus{
				{Name: "debugger", ContainerID: "containerd://" + debugID},
			},
		},
	}
}

func makeChildCgroup(t *testing.T, parent, name string) uint64 {
	t.Helper()
	dir := filepath.Join(parent, name)
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

func verifierFixture(t *testing.T, getPod podGetter) (*inheritedContainerVerifier, string) {
	t.Helper()
	parent := t.TempDir()
	v := newInheritedContainerVerifier("app", staticParents{namespace: "ns", pod: "web", path: parent, parent: 7}, getPod)
	return v, parent
}

func staticPod(pod *corev1.Pod) podGetter {
	return func(context.Context, string, string) (*corev1.Pod, error) { return pod, nil }
}

func TestTheVerifierAdmitsOnlyTheSelectedContainer(t *testing.T) {
	v, parent := verifierFixture(t, staticPod(verifierPod()))
	cases := []struct {
		dir  string
		want tracerpkg.InheritedCgroupVerdict
	}{
		{"cri-containerd-" + selectedID + ".scope", tracerpkg.InheritedCgroupAdmit},
		{"cri-containerd-" + siblingID + ".scope", tracerpkg.InheritedCgroupRefuse},
		{"cri-containerd-" + debugID + ".scope", tracerpkg.InheritedCgroupRefuse},
	}
	for _, c := range cases {
		child := makeChildCgroup(t, parent, c.dir)
		if got := v.check(context.Background(), inheritedCheck{child: child, parent: 7}); got != c.want {
			t.Errorf("%s: verdict %d, want %d", c.dir, got, c.want)
		}
	}
}

func TestTheVerifierWaitsForTheKubeletToReportANewContainer(t *testing.T) {
	v, parent := verifierFixture(t, staticPod(verifierPod()))
	child := makeChildCgroup(t, parent, "cri-containerd-"+unknownID+".scope")
	if got := v.check(context.Background(), inheritedCheck{child: child, parent: 7}); got != tracerpkg.InheritedCgroupUndecided {
		t.Errorf("verdict %d for a container the pod status does not list yet, want undecided", got)
	}

	failing := func(context.Context, string, string) (*corev1.Pod, error) { return nil, errors.New("apiserver down") }
	v2, parent2 := verifierFixture(t, failing)
	child2 := makeChildCgroup(t, parent2, "cri-containerd-"+selectedID+".scope")
	if got := v2.check(context.Background(), inheritedCheck{child: child2, parent: 7}); got != tracerpkg.InheritedCgroupUndecided {
		t.Errorf("verdict %d on an API failure, want undecided so it is retried", got)
	}
}

func TestTheVerifierRefusesWhatCannotBeAContainerOfTheTarget(t *testing.T) {
	v, parent := verifierFixture(t, staticPod(verifierPod()))
	notAContainer := makeChildCgroup(t, parent, "init.scope")
	if got := v.check(context.Background(), inheritedCheck{child: notAContainer, parent: 7}); got != tracerpkg.InheritedCgroupRefuse {
		t.Errorf("a non-container cgroup: verdict %d", got)
	}
	if got := v.check(context.Background(), inheritedCheck{child: notAContainer, parent: 8}); got != tracerpkg.InheritedCgroupRefuse {
		t.Errorf("an untargeted parent: verdict %d", got)
	}
	if got := v.check(context.Background(), inheritedCheck{child: notAContainer + 99999, parent: 7}); got != tracerpkg.InheritedCgroupRefuse {
		t.Errorf("a cgroup already gone: verdict %d", got)
	}
	gone := newInheritedContainerVerifier("app", staticParents{namespace: "ns", pod: "web", path: filepath.Join(parent, "missing"), parent: 7}, staticPod(verifierPod()))
	if got := gone.check(context.Background(), inheritedCheck{child: notAContainer, parent: 7}); got != tracerpkg.InheritedCgroupRefuse {
		t.Errorf("a parent directory that is gone: verdict %d", got)
	}
	nilPod := newInheritedContainerVerifier("app", staticParents{namespace: "ns", pod: "web", path: parent, parent: 7}, staticPod(nil))
	child := makeChildCgroup(t, parent, "cri-containerd-"+selectedID+".scope")
	if got := nilPod.check(context.Background(), inheritedCheck{child: child, parent: 7}); got != tracerpkg.InheritedCgroupUndecided {
		t.Errorf("a nil pod: verdict %d", got)
	}
}

func TestVerdictQueuesEachCgroupOnceAndRetriesAfterTheInterval(t *testing.T) {
	v, _ := verifierFixture(t, staticPod(verifierPod()))
	clock := time.Unix(1000, 0)
	v.now = func() time.Time { return clock }

	if got := v.Verdict(11, 7); got != tracerpkg.InheritedCgroupUndecided {
		t.Fatalf("first verdict %d, want undecided", got)
	}
	if got := v.Verdict(11, 7); got != tracerpkg.InheritedCgroupUndecided || len(v.queue) != 1 {
		t.Fatalf("verdict %d with %d queued; a cgroup already queued must not be queued again", got, len(v.queue))
	}
	<-v.queue
	v.record(11, tracerpkg.InheritedCgroupUndecided)
	v.Verdict(11, 7)
	if len(v.queue) != 0 {
		t.Fatal("rechecked before the retry interval passed")
	}
	clock = clock.Add(v.retry)
	v.Verdict(11, 7)
	if len(v.queue) != 1 {
		t.Fatal("not rechecked after the retry interval")
	}
	<-v.queue
	v.record(11, tracerpkg.InheritedCgroupAdmit)
	if got := v.Verdict(11, 7); got != tracerpkg.InheritedCgroupAdmit {
		t.Fatalf("verdict %d after admission", got)
	}
}

func TestAContainerTheStatusNeverListsIsRefusedAfterTheLastCheck(t *testing.T) {
	v, _ := verifierFixture(t, staticPod(verifierPod()))
	v.maxChecks = 3
	for i := 0; i < 3; i++ {
		v.record(11, tracerpkg.InheritedCgroupUndecided)
	}
	if got := v.Verdict(11, 7); got != tracerpkg.InheritedCgroupRefuse {
		t.Errorf("verdict %d after %d undecided checks, want refused", got, v.maxChecks)
	}
}

func TestAFullQueueLeavesTheCgroupToBeQueuedLater(t *testing.T) {
	v, _ := verifierFixture(t, staticPod(verifierPod()))
	v.queue = make(chan inheritedCheck)

	v.Verdict(11, 7)
	if v.verdicts[11].queued {
		t.Error("a cgroup that did not fit in the queue is marked queued and is never checked")
	}
}

func TestWithoutAPIAccessEveryNewContainerIsRefused(t *testing.T) {
	v, _ := verifierFixture(t, nil)
	if got := v.Verdict(11, 7); got != tracerpkg.InheritedCgroupRefuse {
		t.Errorf("verdict %d with no way to look the container up, want refused", got)
	}
}

func TestRefusedVerdictsArePrunedAtTheLimit(t *testing.T) {
	v, _ := verifierFixture(t, staticPod(verifierPod()))
	for i := uint64(0); i < inheritedVerdictLimit; i++ {
		v.verdicts[i] = &inheritedVerdict{verdict: tracerpkg.InheritedCgroupRefuse}
	}
	v.verdicts[inheritedVerdictLimit] = &inheritedVerdict{verdict: tracerpkg.InheritedCgroupAdmit}

	v.Verdict(inheritedVerdictLimit+1, 7)

	if len(v.verdicts) != 2 {
		t.Fatalf("%d verdicts kept, want the admitted one and the new one", len(v.verdicts))
	}
	if v.verdicts[inheritedVerdictLimit].verdict != tracerpkg.InheritedCgroupAdmit {
		t.Error("an admitted verdict was pruned")
	}
}

func TestTheVerifierLoopChecksQueuedCgroupsUntilCancelled(t *testing.T) {
	v, parent := verifierFixture(t, staticPod(verifierPod()))
	child := makeChildCgroup(t, parent, "cri-containerd-"+selectedID+".scope")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { v.run(ctx); close(done) }()

	v.Verdict(child, 7)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && v.Verdict(child, 7) != tracerpkg.InheritedCgroupAdmit {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if got := v.Verdict(child, 7); got != tracerpkg.InheritedCgroupAdmit {
		t.Fatalf("verdict %d after the loop ran", got)
	}
}

func TestRecordingACgroupNeverAskedAboutStillStoresTheVerdict(t *testing.T) {
	v, _ := verifierFixture(t, staticPod(verifierPod()))
	v.record(42, tracerpkg.InheritedCgroupRefuse)
	if v.verdicts[42].verdict != tracerpkg.InheritedCgroupRefuse {
		t.Error("verdict lost")
	}
}

func TestContainerIDFromCgroupDir(t *testing.T) {
	cases := map[string]string{
		"cri-containerd-" + selectedID + ".scope": selectedID,
		"crio-" + selectedID + ".scope":           selectedID,
		"docker-" + selectedID + ".scope":         selectedID,
		"containerd-" + selectedID + ".scope":     selectedID,
		selectedID:                                selectedID,
		"cri-containerd-abc.scope":                "",
		"init.scope":                              "",
		strings.Repeat("g", 64):                   "",
		strings.ToUpper(selectedID):               "",
	}
	for dir, want := range cases {
		if got := containerIDFromCgroupDir(dir); got != want {
			t.Errorf("containerIDFromCgroupDir(%q) = %q, want %q", dir, got, want)
		}
	}
}

func TestContainerNameForIDSearchesEveryKindOfContainer(t *testing.T) {
	pod := verifierPod()
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "init", ContainerID: "cri-o://" + unknownID}}
	for id, want := range map[string]string{selectedID: "app", debugID: "debugger", unknownID: "init"} {
		if got, ok := containerNameForID(pod, id); !ok || got != want {
			t.Errorf("containerNameForID(%s) = %q, %v; want %q", id[:4], got, ok, want)
		}
	}
	if _, ok := containerNameForID(pod, strings.Repeat("e", 64)); ok {
		t.Error("an unlisted ID was found")
	}
}

type clientsetResolver struct {
	kubernetes.PodResolverInterface
	cs k8s.Interface
}

func (r clientsetResolver) GetClientset() k8s.Interface { return r.cs }

func TestResolverPodGetterReadsThroughTheClientset(t *testing.T) {
	cs := fake.NewSimpleClientset(verifierPod())
	get := resolverPodGetter(clientsetResolver{cs: cs})
	if get == nil {
		t.Fatal("no getter for a resolver with a clientset")
	}
	pod, err := get(context.Background(), "ns", "web")
	if err != nil || pod.Name != "web" {
		t.Fatalf("get = %v, %v", pod, err)
	}
	if resolverPodGetter(clientsetResolver{}) != nil {
		t.Error("a getter for a resolver without a clientset")
	}
	if resolverPodGetter(struct{}{}) != nil {
		t.Error("a getter for a resolver that provides no clientset")
	}
}

type filterRecordingTracer struct {
	ebpf.TracerInterface
	mu     sync.Mutex
	filter tracerpkg.InheritedCgroupFilter
}

func (f *filterRecordingTracer) SetInheritedCgroupFilter(fn tracerpkg.InheritedCgroupFilter) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filter = fn
}

func TestRestartInheritanceIsNarrowedOnlyWhenAContainerIsSelected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	parents := staticParents{parent: 7}

	whole := &filterRecordingTracer{}
	narrowRestartInheritance(ctx, whole, "", parents, staticPod(verifierPod()))
	if whole.filter != nil {
		t.Error("tracing whole pods installed an inheritance filter")
	}

	narrowed := &filterRecordingTracer{}
	narrowRestartInheritance(ctx, narrowed, "app", parents, staticPod(verifierPod()))
	if narrowed.filter == nil {
		t.Fatal("--container did not install an inheritance filter")
	}

	offline := &filterRecordingTracer{}
	narrowRestartInheritance(ctx, offline, "app", parents, nil)
	if offline.filter == nil || offline.filter(1, 7) != tracerpkg.InheritedCgroupRefuse {
		t.Error("without API access a narrowed target must refuse new containers")
	}

	narrowRestartInheritance(ctx, &plainTracer{}, "app", parents, nil)
}

func TestTheSourceIndexReportsEachTargetedPodCgroup(t *testing.T) {
	pod := t.TempDir()
	container := filepath.Join(pod, "cri-containerd-"+selectedID+".scope")
	if err := os.Mkdir(container, 0o750); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(pod, &st); err != nil {
		t.Fatal(err)
	}
	idx := newSourcePodIndex([]*kubernetes.PodInfo{{
		Namespace: "ns", PodName: "web",
		Containers: []kubernetes.ContainerTarget{{Name: "app", ID: selectedID, CgroupPath: container}},
	}})

	ns, name, path, ok := idx.parentTarget(st.Ino)
	if !ok || ns != "ns" || name != "web" || path != pod {
		t.Fatalf("parentTarget = %q %q %q %v", ns, name, path, ok)
	}
	if _, _, _, ok := idx.parentTarget(st.Ino + 1); ok {
		t.Error("an untargeted cgroup reported a pod")
	}
	var nilIdx *sourcePodIndex
	if _, _, _, ok := nilIdx.parentTarget(st.Ino); ok {
		t.Error("a nil index reported a pod")
	}
}

func TestChildCgroupDirIgnoresFilesBesideTheCgroups(t *testing.T) {
	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, "cgroup.procs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	child := makeChildCgroup(t, parent, "cri-containerd-"+selectedID+".scope")

	dir, ok := childCgroupDir(parent, child)
	if !ok || dir != "cri-containerd-"+selectedID+".scope" {
		t.Fatalf("childCgroupDir = %q, %v", dir, ok)
	}
}
