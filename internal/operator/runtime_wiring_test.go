package operator

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func nonConnectingManager(t *testing.T) ctrl.Manager {
	t.Helper()
	scheme, err := NewScheme()
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}
	mgr, err := ctrl.NewManager(&rest.Config{Host: "http://127.0.0.1:1"}, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Skipf("could not build non-connecting manager: %v", err)
	}
	return mgr
}

func TestNewSchemeRegistersBothGroups(t *testing.T) {
	s, err := NewScheme()
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}
	if !s.Recognizes(corev1.SchemeGroupVersion.WithKind("Pod")) {
		t.Error("client-go core types must be registered")
	}
	if !s.Recognizes(podtracev1alpha1.GroupVersion.WithKind("TracerConfig")) {
		t.Error("podtrace types must be registered")
	}
}

func TestRegisterWebhooksWiresEveryValidator(t *testing.T) {
	if err := registerWebhooks(nonConnectingManager(t)); err != nil {
		t.Fatalf("registerWebhooks: %v", err)
	}
}

func TestStripNodeStatusDropsTheHeavyFields(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:          "n1",
			Labels:        map[string]string{"pool": "a"},
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubelet"}},
		},
		Spec: corev1.NodeSpec{Taints: []corev1.Taint{{Key: "dedicated", Effect: corev1.TaintEffectNoSchedule}}},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady}},
			Images:     []corev1.ContainerImage{{Names: []string{"a-very-large-image-list"}}},
		},
	}

	out, err := stripNodeStatus(node)
	if err != nil {
		t.Fatalf("stripNodeStatus: %v", err)
	}
	stripped, ok := out.(*corev1.Node)
	if !ok {
		t.Fatalf("stripNodeStatus returned %T, want *corev1.Node", out)
	}
	if len(stripped.Status.Images) != 0 || len(stripped.Status.Conditions) != 0 {
		t.Error("node status is the bulk of the object and nothing in the operator reads it")
	}
	if stripped.ManagedFields != nil {
		t.Error("managed fields are dead weight in the cache")
	}
	if stripped.Labels["pool"] != "a" {
		t.Error("labels decide fleet membership and must survive")
	}
	if len(stripped.Spec.Taints) != 1 {
		t.Error("taints decide fleet membership and must survive")
	}
}

func TestStripNodeStatusPassesThroughOtherTypes(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p1"}}
	out, err := stripNodeStatus(pod)
	if err != nil {
		t.Fatalf("stripNodeStatus: %v", err)
	}
	if out != any(pod) {
		t.Error("a non-Node object must pass through untouched")
	}
}

func TestSessionJobNameStaysWithinLabelLimits(t *testing.T) {
	longNode := strings.Repeat("node-with-a-very-long-name", 6)
	name := SessionJobName(types.UID("11111111-2222-3333-4444-555555555555"), longNode)
	if len(name) > 63 {
		t.Errorf("Job name %q is %d chars; must stay within the 63-char object-name budget", name, len(name))
	}
	if strings.HasSuffix(name, "-") || strings.HasSuffix(name, ".") {
		t.Errorf("Job name %q must not end in a separator", name)
	}
}

func TestSessionJobNameHandlesUnusableNodeNames(t *testing.T) {
	name := SessionJobName(types.UID("11111111-2222-3333-4444-555555555555"), "...")
	if name == "" {
		t.Fatal("a node name that sanitises to nothing must still yield a usable Job name")
	}
	if strings.Contains(name, "..") {
		t.Errorf("Job name %q is not a valid DNS name", name)
	}

	a := SessionJobName(types.UID("u"), "node-a")
	b := SessionJobName(types.UID("u"), "node-b")
	if a == b {
		t.Error("distinct nodes must produce distinct Job names")
	}
}

func TestJobHelpersTolerateNilTracerConfig(t *testing.T) {
	if got := tolerationsFrom(nil); got != nil {
		t.Errorf("tolerationsFrom(nil) = %v, want nil", got)
	}
	if got := priorityClassNameFrom(nil); got != "" {
		t.Errorf("priorityClassNameFrom(nil) = %q, want empty", got)
	}

	tc := &podtracev1alpha1.TracerConfig{Spec: podtracev1alpha1.TracerConfigSpec{
		Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
	}}
	tc.Spec.Agent.PriorityClassName = "system-node-critical"
	if len(tolerationsFrom(tc)) != 1 {
		t.Error("tolerations must pass through when a config is present")
	}
	if priorityClassNameFrom(tc) != "system-node-critical" {
		t.Error("priorityClassName must pass through when a config is present")
	}
}

func TestSessionTracerConfigsZeroValueIsSafe(t *testing.T) {
	var empty sessionTracerConfigs

	if got := empty.forNode("n1"); got != nil {
		t.Errorf("forNode on a zero value = %v, want nil", got)
	}
	if got := empty.primary(); got != nil {
		t.Errorf("primary on a zero value = %v, want nil", got)
	}
	if got := empty.namespaceForNode("n1", "fallback"); got != "fallback" {
		t.Errorf("namespaceForNode on a zero value = %q, want the fallback", got)
	}
}
