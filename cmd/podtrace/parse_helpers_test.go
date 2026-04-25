package main

import (
	"reflect"
	"slices"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/kubernetes"
)

func TestParseCSV(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"single", "a", []string{"a"}},
		{"trims and dedupes empties", " a , b , , c ", []string{"a", "b", "c"}},
		{"all empty after trim", " , ,  ,  ", []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseCSV(c.in)
			if c.want == nil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestParsePprofPorts(t *testing.T) {
	cases := []struct {
		in       string
		wantHas  []int
		wantSize int // 0 means default fallback
	}{
		{"6060,8080", []int{6060, 8080}, 2},
		{"  6060 , 9090 , 7777  ", []int{6060, 9090, 7777}, 3},
		// Out-of-range or non-numeric → filtered, falls back to defaults.
		{"99999,abc,-1", nil, 5},
		// All bad → defaults.
		{"", nil, 5},
	}
	for _, c := range cases {
		got := parsePprofPorts(c.in)
		if c.wantSize > 0 && len(got) != c.wantSize {
			t.Errorf("%q: len=%d want %d (got=%v)", c.in, len(got), c.wantSize, got)
		}
		for _, w := range c.wantHas {
			if !slices.Contains(got, w) {
				t.Errorf("%q: missing %d (got %v)", c.in, w, got)
			}
		}
	}
}

func TestParsePodRef(t *testing.T) {
	cases := []struct {
		in        string
		defaultNS string
		wantNS    string
		wantPod   string
	}{
		{"pod-a", "default", "default", "pod-a"},
		{"team/api", "default", "team", "api"},
		{"  ns/pod  ", "x", "ns", "pod"},
		{"", "fallback", "fallback", ""},
	}
	for _, c := range cases {
		ns, pod := parsePodRef(c.in, c.defaultNS)
		if ns != c.wantNS || pod != c.wantPod {
			t.Errorf("parsePodRef(%q,%q) = (%q,%q), want (%q,%q)", c.in, c.defaultNS, ns, pod, c.wantNS, c.wantPod)
		}
	}
}

func TestCgroupIDFromPath(t *testing.T) {
	if _, err := cgroupIDFromPath("/no/such/path/should/not/exist"); err == nil {
		t.Error("expected error for missing path")
	}
	id, err := cgroupIDFromPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Error("expected non-zero inode for tmpdir")
	}
}

func TestDetectServiceMesh(t *testing.T) {
	cases := []struct {
		in   map[string]string
		want string
	}{
		{nil, ""},
		{map[string]string{}, ""},
		{map[string]string{"sidecar.istio.io/status": "{}"}, "istio"},
		{map[string]string{"istio.io/rev": "1.20"}, "istio"},
		{map[string]string{"linkerd.io/proxy-version": "x"}, "linkerd"},
		{map[string]string{"kuma.io/sidecar-injected": "true"}, "kuma"},
		{map[string]string{"unrelated": "x"}, ""},
	}
	for _, c := range cases {
		if got := detectServiceMesh(c.in); got != c.want {
			t.Errorf("detectServiceMesh(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSourcePodIndex_Resolve covers the cgroup-keyed lookup path.
// The Replace path stores by both cgroup ID and namespace/name; Resolve
// hits only the cgroup map. Use a path whose Stat will succeed (TempDir)
// so Replace actually stores a cgroup-id keyed entry.
func TestSourcePodIndex_Resolve(t *testing.T) {
	// Build a tmp dir whose inode we can resolve to a cgroup id.
	dir := t.TempDir()
	id, err := cgroupIDFromPath(dir)
	if err != nil {
		t.Fatal(err)
	}

	idx := &sourcePodIndex{}
	idx.Replace([]*kubernetes.PodInfo{
		{PodName: "p", Namespace: "ns", CgroupPath: dir},
		nil, // skipped
		{PodName: "no-path", Namespace: "ns", CgroupPath: "/non/existent/should/skip"},
	})

	got := idx.Resolve(&events.Event{CgroupID: id})
	if got == nil || got.PodName != "p" {
		t.Errorf("got %+v, want PodName=p", got)
	}

	// Unknown cgroup → nil.
	if g := idx.Resolve(&events.Event{CgroupID: 999999}); g != nil {
		t.Errorf("expected nil for unknown cgroup, got %+v", g)
	}
	// Nil event / nil receiver → nil.
	var nilIdx *sourcePodIndex
	if g := nilIdx.Resolve(&events.Event{CgroupID: id}); g != nil {
		t.Errorf("nil receiver should return nil")
	}
	if g := idx.Resolve(nil); g != nil {
		t.Errorf("nil event should return nil")
	}
}

func TestBuildK8sContextMap_NilContext(t *testing.T) {
	if got := buildK8sContextMap(nil, nil); got != nil {
		t.Errorf("nil enriched should yield nil, got %v", got)
	}
	if got := buildK8sContextMap(&kubernetes.EnrichedEvent{}, nil); got != nil {
		t.Errorf("nil KubernetesContext should yield nil, got %v", got)
	}
}

func TestBuildK8sContextMap_PopulatesAllFields(t *testing.T) {
	enriched := &kubernetes.EnrichedEvent{
		KubernetesContext: &kubernetes.KubernetesContext{
			SourceNamespace:  "src-ns",
			TargetPodName:    "tpod",
			ServiceName:      "svc",
			TargetNamespace:  "tns",
			TargetLabels:     map[string]string{"sidecar.istio.io/status": "{}"},
			ServiceNamespace: "snamespace",
			IsExternal:       true,
		},
	}
	source := &kubernetes.PodInfo{
		PodName: "src-pod", Namespace: "src-ns",
		Labels:    map[string]string{"linkerd.io/proxy-version": "x"},
		OwnerKind: "Deployment", OwnerName: "src-d",
	}
	got := buildK8sContextMap(enriched, source)
	if got["target_mesh"] != "istio" {
		t.Errorf("expected target_mesh=istio, got %v", got["target_mesh"])
	}
	if got["source_mesh"] != "linkerd" {
		t.Errorf("expected source_mesh=linkerd, got %v", got["source_mesh"])
	}
	if got["source_pod"] != "src-pod" {
		t.Errorf("source_pod = %v", got["source_pod"])
	}
	if got["target_pod"] != "tpod" {
		t.Errorf("target_pod = %v", got["target_pod"])
	}
	if got["is_external"] != true {
		t.Errorf("is_external = %v", got["is_external"])
	}
}

func TestResolveSourcePod_NilResolverIsSafe(t *testing.T) {
	if got := resolveSourcePod(nil, &events.Event{}); got != nil {
		t.Error("expected nil for nil resolver")
	}
	called := false
	got := resolveSourcePod(func(*events.Event) *kubernetes.PodInfo {
		called = true
		return &kubernetes.PodInfo{PodName: "x"}
	}, &events.Event{})
	if !called || got == nil || got.PodName != "x" {
		t.Errorf("resolver not called or wrong return: %+v", got)
	}
}
