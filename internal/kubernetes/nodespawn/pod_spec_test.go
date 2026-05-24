package nodespawn

import (
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func baseOpts() PodSpecOptions {
	return PodSpecOptions{
		NodeName:              "worker-1",
		Namespace:             "kube-system",
		Image:                 "ghcr.io/gma1k/podtrace:v1.2.3",
		ImagePullPolicy:       corev1.PullIfNotPresent,
		Args:                  []string{"--pods", "kube-system/api", "--diagnose", "5s"},
		ActiveDeadlineSeconds: 300,
		OwnerHost:             "laptop",
		OwnerPID:              1234,
	}
}

func TestBuildPodSpec_RequiredFields(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*PodSpecOptions)
	}{
		{"no node", func(o *PodSpecOptions) { o.NodeName = "" }},
		{"no namespace", func(o *PodSpecOptions) { o.Namespace = "" }},
		{"no image", func(o *PodSpecOptions) { o.Image = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := baseOpts()
			tc.mut(&o)
			if _, err := BuildPodSpec(o); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestBuildPodSpec_NameWithinDNSBudget(t *testing.T) {
	o := baseOpts()
	o.NodeName = "gke-very-long-cluster-name-default-pool-12345678-abcd-this-should-truncate"
	got, err := BuildPodSpec(o)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(got.Name) > 63 {
		t.Errorf("name %q exceeds 63 chars (got %d)", got.Name, len(got.Name))
	}
	if !strings.HasPrefix(got.Name, "podtrace-cli-") {
		t.Errorf("name %q missing podtrace-cli- prefix", got.Name)
	}
}

func TestBuildPodSpec_NodeNameSanitized(t *testing.T) {
	o := baseOpts()
	o.NodeName = "WORKER.example.com"
	got, err := BuildPodSpec(o)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if strings.ContainsAny(got.Name, ".") || strings.ContainsAny(got.Name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Errorf("name %q not DNS-1123 safe", got.Name)
	}
}

func TestBuildPodSpec_SecurityContext(t *testing.T) {
	got, err := BuildPodSpec(baseOpts())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !got.Spec.HostPID {
		t.Errorf("expected HostPID=true")
	}
	if got.Spec.Containers[0].SecurityContext.Privileged == nil || !*got.Spec.Containers[0].SecurityContext.Privileged {
		t.Errorf("expected privileged container")
	}
	caps := got.Spec.Containers[0].SecurityContext.Capabilities.Add
	wantCaps := map[string]bool{"BPF": true, "SYS_ADMIN": true, "PERFMON": true, "SYS_RESOURCE": true, "NET_ADMIN": true}
	for _, c := range caps {
		delete(wantCaps, string(c))
	}
	if len(wantCaps) > 0 {
		t.Errorf("missing capabilities: %v", wantCaps)
	}
}

func TestBuildPodSpec_HostMountsAndEnv(t *testing.T) {
	got, err := BuildPodSpec(baseOpts())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	container := got.Spec.Containers[0]

	wantEnv := map[string]string{
		"PODTRACE_NODE_LOCAL":  "1",
		"PODTRACE_PROC_BASE":   "/host/proc",
		"PODTRACE_CGROUP_BASE": "/host/sys/fs/cgroup",
	}
	for _, e := range container.Env {
		if exp, ok := wantEnv[e.Name]; ok {
			if e.Value != exp {
				t.Errorf("env %s = %q, want %q", e.Name, e.Value, exp)
			}
			delete(wantEnv, e.Name)
		}
	}
	if len(wantEnv) > 0 {
		t.Errorf("missing env entries: %v", wantEnv)
	}

	mountPaths := map[string]bool{}
	for _, m := range container.VolumeMounts {
		mountPaths[m.MountPath] = true
	}
	wantMounts := []string{"/sys/fs/bpf", "/sys/kernel/btf", "/host/proc", "/sys/fs/cgroup", "/host/sys/fs/cgroup", "/run/containerd"}
	for _, p := range wantMounts {
		if !mountPaths[p] {
			t.Errorf("missing mount path %s", p)
		}
	}
}

func TestBuildPodSpec_NodeSelectorPinsToTargetNode(t *testing.T) {
	got, err := BuildPodSpec(baseOpts())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got.Spec.NodeSelector["kubernetes.io/hostname"] != "worker-1" {
		t.Errorf("nodeSelector hostname = %q, want worker-1", got.Spec.NodeSelector["kubernetes.io/hostname"])
	}
}

func TestBuildPodSpec_LabelsForReaper(t *testing.T) {
	got, err := BuildPodSpec(baseOpts())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got.Labels[LabelManagedBy] != ManagedByValue {
		t.Errorf("managed-by = %q, want %q", got.Labels[LabelManagedBy], ManagedByValue)
	}
	if got.Labels[LabelComponent] != ComponentValue {
		t.Errorf("component = %q, want %q", got.Labels[LabelComponent], ComponentValue)
	}
	if got.Labels[LabelNode] != "worker-1" {
		t.Errorf("node label = %q, want worker-1", got.Labels[LabelNode])
	}
	if got.Labels[LabelOwnerHost] != "laptop" {
		t.Errorf("owner-host label = %q, want laptop", got.Labels[LabelOwnerHost])
	}
	if got.Labels[LabelOwnerPID] != "1234" {
		t.Errorf("owner-pid label = %q, want 1234", got.Labels[LabelOwnerPID])
	}
	if _, ok := got.Labels[LabelCreatedAt]; !ok {
		t.Errorf("missing created-at label")
	}
}

func TestBuildPodSpec_ActiveDeadlineApplied(t *testing.T) {
	got, err := BuildPodSpec(baseOpts())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got.Spec.ActiveDeadlineSeconds == nil || *got.Spec.ActiveDeadlineSeconds != 300 {
		t.Errorf("activeDeadlineSeconds = %v, want 300", got.Spec.ActiveDeadlineSeconds)
	}
}

func TestBuildPodSpec_ArgsCopiedNotAliased(t *testing.T) {
	opts := baseOpts()
	got, err := BuildPodSpec(opts)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	original := append([]string(nil), opts.Args...)
	got.Spec.Containers[0].Args[0] = "MUTATED"
	if !reflect.DeepEqual(opts.Args, original) {
		t.Errorf("BuildPodSpec aliased caller's Args slice")
	}
}

func TestBuildPodSpec_OwnerHostSanitized(t *testing.T) {
	opts := baseOpts()
	opts.OwnerHost = "my.workstation.local!"
	got, err := BuildPodSpec(opts)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	v := got.Labels[LabelOwnerHost]
	for _, c := range v {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			t.Errorf("owner-host label %q has invalid char %q", v, c)
		}
	}
}

func TestSanitizeName(t *testing.T) {
	tests := map[string]string{
		"WORKER.example.com": "worker-example-com",
		"--node--1--":        "node-1",
		"???":                "node",
		"":                   "node",
	}
	for in, want := range tests {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}
