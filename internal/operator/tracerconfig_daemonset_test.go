package operator

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func tc(mod func(*podtracev1alpha1.TracerConfig)) *podtracev1alpha1.TracerConfig {
	t := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image: "ghcr.io/podtrace/podtrace:test",
		},
	}
	if mod != nil {
		mod(t)
	}
	return t
}

func TestBuildAgentDaemonSetSpec_SelectorStability(t *testing.T) {
	// The DaemonSet selector is IMMUTABLE after creation — agent pods
	// would orphan themselves if it changed. Lock in the key labels the
	// selector depends on.
	spec := buildAgentDaemonSetSpec(tc(nil), "podtrace-system")
	want := map[string]string{
		LabelManagedBy:    ManagedByValue,
		LabelComponent:    ComponentAgent,
		LabelTracerConfig: "default",
	}
	for k, v := range want {
		if spec.Selector.MatchLabels[k] != v {
			t.Errorf("selector[%q]=%q want %q", k, spec.Selector.MatchLabels[k], v)
		}
	}
	for k, v := range want {
		if spec.Template.Labels[k] != v {
			t.Errorf("template labels[%q]=%q want %q", k, spec.Template.Labels[k], v)
		}
	}
}

func TestBuildAgentDaemonSetSpec_PrivilegedContainer(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(nil), "podtrace-system")
	c := spec.Template.Spec.Containers[0]
	if c.SecurityContext == nil {
		t.Fatal("SecurityContext is nil")
	}
	if c.SecurityContext.Privileged == nil || !*c.SecurityContext.Privileged {
		t.Error("agent container must be privileged")
	}
	if c.SecurityContext.RunAsUser == nil || *c.SecurityContext.RunAsUser != 0 {
		t.Error("agent must run as root (user 0)")
	}
	// Must request the four eBPF-relevant capabilities.
	wantCaps := map[corev1.Capability]bool{
		"BPF": false, "SYS_ADMIN": false, "PERFMON": false, "NET_ADMIN": false,
	}
	for _, added := range c.SecurityContext.Capabilities.Add {
		if _, ok := wantCaps[added]; ok {
			wantCaps[added] = true
		}
	}
	for cap, ok := range wantCaps {
		if !ok {
			t.Errorf("missing required capability: %s", cap)
		}
	}
}

func TestBuildAgentDaemonSetSpec_HostMounts(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(nil), "podtrace-system")
	expected := map[string]string{
		"bpf":    "/sys/fs/bpf",
		"btf":    "/sys/kernel/btf",
		"proc":   "/proc",
		"cgroup": "/sys/fs/cgroup",
	}
	found := map[string]string{}
	for _, v := range spec.Template.Spec.Volumes {
		if v.HostPath != nil {
			found[v.Name] = v.HostPath.Path
		}
	}
	for name, path := range expected {
		if found[name] != path {
			t.Errorf("volume %q path=%q want %q", name, found[name], path)
		}
	}
	// HostPID MUST be on for pid → cgroup traversal.
	if !spec.Template.Spec.HostPID {
		t.Error("HostPID must be true")
	}
}

func TestBuildAgentDaemonSetSpec_NodeNameEnvInjected(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(nil), "podtrace-system")
	c := spec.Template.Spec.Containers[0]
	foundNodeName := false
	for _, e := range c.Env {
		if e.Name == "NODE_NAME" && e.ValueFrom != nil && e.ValueFrom.FieldRef != nil && e.ValueFrom.FieldRef.FieldPath == "spec.nodeName" {
			foundNodeName = true
		}
	}
	if !foundNodeName {
		t.Error("NODE_NAME env var (downward API) missing; informer filter will break")
	}
}

func TestBuildAgentDaemonSetSpec_ArgsCarryTracerConfigName(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Name = "alt"
	}), "podtrace-system")
	args := spec.Template.Spec.Containers[0].Args
	// Expect the `agent` subcommand with system-namespace and tracer-config flags.
	if len(args) == 0 || args[0] != "agent" {
		t.Fatalf("args[0]=%q want agent (full args: %v)", args[0], args)
	}
	joined := ""
	for _, a := range args {
		joined += a + " "
	}
	if !contains(joined, "--tracer-config alt") {
		t.Errorf("--tracer-config name not wired: %v", args)
	}
	if !contains(joined, "--system-namespace podtrace-system") {
		t.Errorf("--system-namespace not wired: %v", args)
	}
}

func TestBuildAgentDaemonSetSpec_PriorityClassDefault(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(nil), "podtrace-system")
	if spec.Template.Spec.PriorityClassName != "system-node-critical" {
		t.Errorf("priorityClassName=%q want system-node-critical", spec.Template.Spec.PriorityClassName)
	}
	// Explicit override wins.
	spec = buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.PriorityClassName = "podtrace-high"
	}), "podtrace-system")
	if spec.Template.Spec.PriorityClassName != "podtrace-high" {
		t.Errorf("priorityClassName override not applied: %q", spec.Template.Spec.PriorityClassName)
	}
}

func TestBuildAgentDaemonSetSpec_ProbesWireHealthPort(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(nil), "podtrace-system")
	c := spec.Template.Spec.Containers[0]
	if c.LivenessProbe == nil || c.LivenessProbe.HTTPGet == nil {
		t.Fatal("livenessProbe not wired")
	}
	if c.LivenessProbe.HTTPGet.Port.StrVal != "health" {
		t.Errorf("livenessProbe port=%q want health", c.LivenessProbe.HTTPGet.Port.StrVal)
	}
	if c.ReadinessProbe == nil {
		t.Error("readinessProbe not wired")
	}
}

func contains(haystack, needle string) bool {
	return indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	if len(n) > len(h) {
		return -1
	}
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
