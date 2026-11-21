package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gma1k/podtrace/internal/ebpf"
	tracerpkg "github.com/gma1k/podtrace/internal/ebpf/tracer"
	"github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/logger"
)

const (
	inheritedVerifyRetry     = time.Second
	inheritedVerifyMaxChecks = 30
	inheritedVerifyTimeout   = 5 * time.Second
	inheritedVerdictLimit    = 4096
)

type podGetter func(ctx context.Context, namespace, name string) (*corev1.Pod, error)

type parentTargetLookup interface {
	parentTarget(parent uint64) (namespace, pod, path string, ok bool)
}

type inheritedCheck struct {
	child, parent uint64
}

type inheritedVerdict struct {
	verdict tracerpkg.InheritedCgroupVerdict
	checks  int
	next    time.Time
	queued  bool
}

// inheritedContainerVerifier lets a restart of the selected container be
// followed from its first event while keeping every other container of the
// pod out. The kernel inherits any cgroup created under a targeted pod
// cgroup, and a new cgroup's container is not known when it is created, so
// the verifier asks the pod's status which container owns the new cgroup's
// container ID. Until the kubelet reports it, the cgroup's events are
// dropped; once it does, a sibling or a debug container is refused for good.
type inheritedContainerVerifier struct {
	container string
	parents   parentTargetLookup
	getPod    podGetter
	now       func() time.Time
	retry     time.Duration
	maxChecks int

	mu       sync.Mutex
	verdicts map[uint64]*inheritedVerdict
	queue    chan inheritedCheck
	warnOnce sync.Once
}

func newInheritedContainerVerifier(container string, parents parentTargetLookup, getPod podGetter) *inheritedContainerVerifier {
	return &inheritedContainerVerifier{
		container: container,
		parents:   parents,
		getPod:    getPod,
		now:       time.Now,
		retry:     inheritedVerifyRetry,
		maxChecks: inheritedVerifyMaxChecks,
		verdicts:  make(map[uint64]*inheritedVerdict),
		queue:     make(chan inheritedCheck, 64),
	}
}

// Verdict answers the tracer without blocking: a cgroup not yet checked is
// queued for the background check and dropped for now.
func (v *inheritedContainerVerifier) Verdict(child, parent uint64) tracerpkg.InheritedCgroupVerdict {
	if v.getPod == nil {
		v.warnOnce.Do(func() {
			logger.Warn("No Kubernetes API access to tell which container a restarted container cgroup belongs to; "+
				"with --container set, containers that start after tracing began are not traced",
				zap.String("container", v.container))
		})
		return tracerpkg.InheritedCgroupRefuse
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	vd, ok := v.verdicts[child]
	if !ok {
		v.pruneLocked()
		vd = &inheritedVerdict{}
		v.verdicts[child] = vd
	}
	if vd.verdict != tracerpkg.InheritedCgroupUndecided {
		return vd.verdict
	}
	if vd.queued || v.now().Before(vd.next) {
		return tracerpkg.InheritedCgroupUndecided
	}
	select {
	case v.queue <- inheritedCheck{child: child, parent: parent}:
		vd.queued = true
	default:
	}
	return tracerpkg.InheritedCgroupUndecided
}

func (v *inheritedContainerVerifier) pruneLocked() {
	if len(v.verdicts) < inheritedVerdictLimit {
		return
	}
	for id, vd := range v.verdicts {
		if vd.verdict == tracerpkg.InheritedCgroupRefuse {
			delete(v.verdicts, id)
		}
	}
}

func (v *inheritedContainerVerifier) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-v.queue:
			v.record(c.child, v.check(ctx, c))
		}
	}
}

func (v *inheritedContainerVerifier) record(child uint64, verdict tracerpkg.InheritedCgroupVerdict) {
	v.mu.Lock()
	defer v.mu.Unlock()
	vd, ok := v.verdicts[child]
	if !ok {
		vd = &inheritedVerdict{}
		v.verdicts[child] = vd
	}
	vd.queued = false
	vd.checks++
	switch {
	case verdict != tracerpkg.InheritedCgroupUndecided:
		vd.verdict = verdict
	case vd.checks >= v.maxChecks:
		vd.verdict = tracerpkg.InheritedCgroupRefuse
	default:
		vd.next = v.now().Add(v.retry)
	}
}

func (v *inheritedContainerVerifier) check(ctx context.Context, c inheritedCheck) tracerpkg.InheritedCgroupVerdict {
	namespace, podName, parentPath, ok := v.parents.parentTarget(c.parent)
	if !ok || parentPath == "" {
		return tracerpkg.InheritedCgroupRefuse
	}
	dir, found := childCgroupDir(parentPath, c.child)
	if !found {
		return tracerpkg.InheritedCgroupRefuse
	}
	id := containerIDFromCgroupDir(dir)
	if id == "" {
		return tracerpkg.InheritedCgroupRefuse
	}
	lookupCtx, cancel := context.WithTimeout(ctx, inheritedVerifyTimeout)
	defer cancel()
	pod, err := v.getPod(lookupCtx, namespace, podName)
	if err != nil || pod == nil {
		return tracerpkg.InheritedCgroupUndecided
	}
	name, known := containerNameForID(pod, id)
	switch {
	case !known:
		return tracerpkg.InheritedCgroupUndecided
	case name == v.container:
		return tracerpkg.InheritedCgroupAdmit
	default:
		logger.Debug("Not tracing a container that started under a targeted pod: it is not the selected container",
			zap.String("namespace", namespace), zap.String("pod", podName),
			zap.String("container", name), zap.String("selected", v.container))
		return tracerpkg.InheritedCgroupRefuse
	}
}

// childCgroupDir finds the directory under parentPath whose cgroup id is
// child.
func childCgroupDir(parentPath string, child uint64) (string, bool) {
	entries, err := os.ReadDir(parentPath)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.IsDir() {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Ino == child {
			return e.Name(), true
		}
	}
	return "", false
}

// containerIDFromCgroupDir extracts the container ID a runtime names a
// container cgroup after: "cri-containerd-<id>.scope", "crio-<id>.scope",
// "docker-<id>.scope" or a bare "<id>" under cgroupfs.
func containerIDFromCgroupDir(dir string) string {
	trimmed := strings.TrimSuffix(dir, ".scope")
	for _, prefix := range []string{"cri-containerd-", "crio-", "docker-", "containerd-"} {
		if rest, ok := strings.CutPrefix(trimmed, prefix); ok {
			trimmed = rest
			break
		}
	}
	if len(trimmed) != 64 {
		return ""
	}
	for _, r := range trimmed {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return trimmed
}

// containerNameForID returns the name of the pod's container, init
// container or ephemeral container whose status carries the container ID.
func containerNameForID(pod *corev1.Pod, id string) (string, bool) {
	match := func(statuses []corev1.ContainerStatus) (string, bool) {
		for _, cs := range statuses {
			raw := cs.ContainerID
			if i := strings.Index(raw, "://"); i >= 0 {
				raw = raw[i+3:]
			}
			if raw == id {
				return cs.Name, true
			}
		}
		return "", false
	}
	for _, statuses := range [][]corev1.ContainerStatus{
		pod.Status.ContainerStatuses,
		pod.Status.InitContainerStatuses,
		pod.Status.EphemeralContainerStatuses,
	} {
		if name, ok := match(statuses); ok {
			return name, true
		}
	}
	return "", false
}

// resolverPodGetter reads pods through the resolver's clientset, or returns
// nil when the resolver has none.
func resolverPodGetter(resolver any) podGetter {
	provider, ok := resolver.(kubernetes.ClientsetProvider)
	if !ok {
		return nil
	}
	clientset := provider.GetClientset()
	if clientset == nil {
		return nil
	}
	return func(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
		return clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	}
}

type inheritedCgroupFilterSetter interface {
	SetInheritedCgroupFilter(tracerpkg.InheritedCgroupFilter)
}

// narrowRestartInheritance installs the verifier when only one container of
// each target pod is traced. Tracing whole pods needs no filter.
func narrowRestartInheritance(ctx context.Context, tr ebpf.TracerInterface, container string, parents parentTargetLookup, getPod podGetter) {
	if container == "" {
		return
	}
	setter, ok := tr.(inheritedCgroupFilterSetter)
	if !ok {
		return
	}
	v := newInheritedContainerVerifier(container, parents, getPod)
	if getPod != nil {
		go v.run(ctx)
	}
	setter.SetInheritedCgroupFilter(v.Verdict)
}
