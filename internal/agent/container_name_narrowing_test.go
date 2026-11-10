package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/pkg/tracer"
)

func sidecarPodWithCgroups(t *testing.T) *corev1.Pod {
	t.Helper()
	root := filepath.Join(t.TempDir(), "kubepods.slice")
	uidUnder := strings.ReplaceAll(testPodUID, "-", "_")
	podSlice := filepath.Join(root, "kubepods-besteffort.slice", "kubepods-besteffort-pod"+uidUnder+".slice")
	for _, dir := range []string{"cri-containerd-aaa111.scope", "cri-containerd-bbb222.scope"} {
		if err := os.MkdirAll(filepath.Join(podSlice, dir), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	withKubepodsRoot(t, root)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns", UID: types.UID(testPodUID), Labels: map[string]string{"app": "api"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: "proxy"}}},
		Status: corev1.PodStatus{
			Phase:    corev1.PodRunning,
			QOSClass: corev1.PodQOSBestEffort,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", ContainerID: "containerd://aaa111"},
				{Name: "proxy", ContainerID: "containerd://bbb222"},
			},
		},
	}
}

func TestResolveCgroupIDs_ContainerNameKeepsOnlyThatContainer(t *testing.T) {
	pod := sidecarPodWithCgroups(t)

	all, err := resolveCgroupIDs([]*corev1.Pod{pod}, "")
	if err != nil {
		t.Fatalf("resolve all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("unnarrowed IDs = %d, want 3 (pod + 2 containers)", len(all))
	}

	narrowed, err := resolveCgroupIDs([]*corev1.Pod{pod}, "app")
	if err != nil {
		t.Fatalf("resolve app: %v", err)
	}
	if len(narrowed) != 1 {
		t.Fatalf("narrowed IDs = %d, want only the app container's cgroup", len(narrowed))
	}
	var appID uint64
	for _, e := range scanPodCgroups([]*corev1.Pod{pod}) {
		if e.ContainerName == "app" {
			appID = e.CgroupID
		}
	}
	if _, ok := narrowed[appID]; !ok {
		t.Errorf("narrowed set %v does not hold the app container cgroup %d", narrowed, appID)
	}
}

func TestResolveCgroupIDs_UnknownContainerNameIsAnError(t *testing.T) {
	pod := sidecarPodWithCgroups(t)
	ids, err := resolveCgroupIDs([]*corev1.Pod{pod}, "missing")
	if err == nil || !strings.Contains(err.Error(), `"missing"`) {
		t.Fatalf("err = %v, want a resolution error naming the container", err)
	}
	if len(ids) != 0 {
		t.Errorf("ids = %v, want none", ids)
	}
}

func TestMatchPodTraceAgainstPods_ContainerNameSkipsPodsWithoutIt(t *testing.T) {
	withApp := mkPod("default", "with-app", map[string]string{"app": "api"})
	withApp.Spec.Containers = []corev1.Container{{Name: "app"}, {Name: "proxy"}}
	initSidecar := mkPod("default", "init-sidecar", map[string]string{"app": "api"})
	initSidecar.Spec.InitContainers = []corev1.Container{{Name: "app"}}
	ephemeral := mkPod("default", "ephemeral", map[string]string{"app": "api"})
	ephemeral.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "app"}}}
	without := mkPod("default", "without", map[string]string{"app": "api"})
	without.Spec.Containers = []corev1.Container{{Name: "worker"}}

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pt"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:      &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			ContainerName: "app",
		},
	}
	matched, err := MatchPodTraceAgainstPods(pt, []*corev1.Pod{withApp, initSidecar, ephemeral, without}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range matched {
		names = append(names, p.Name)
	}
	if got := strings.Join(names, ","); got != "with-app,init-sidecar,ephemeral" {
		t.Errorf("matched = %s, want the three pods that declare container app", got)
	}
}

func TestReconcile_PassesSpecContainerNameToTheResolver(t *testing.T) {
	const node, sysNS, ns = "node-1", "podtrace-system", "default"
	uid := types.UID("uid-1")
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: uid},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:      &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			ContainerName: "app",
			ExporterRef:   corev1.LocalObjectReference{Name: "ignored"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: ns, Labels: map[string]string{"app": "api"}},
		Spec:       corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "app"}, {Name: "proxy"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).
		WithObjects(pt, pod, makeBundleCM(sysNS, uid, "1")).Build()

	var gotContainer string
	r := &AgentReconciler{
		Client:          c,
		NodeName:        node,
		SystemNamespace: sysNS,
		Router:          NewRouter(nil),
		Metrics:         NewMetrics(),
		TargetsCh:       make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) { return &fakeExporter{name: "fx"}, nil },
		CgroupResolver: func(_ []*corev1.Pod, containerName string) (map[uint64]struct{}, error) {
			gotContainer = containerName
			return map[uint64]struct{}{7: {}}, nil
		},
		exporterCache: map[CRKey]cachedExporter{},
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if gotContainer != "app" {
		t.Errorf("resolver got container %q, want spec.containerName app", gotContainer)
	}
}
