package fleet

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func node(name string, labels map[string]string, taints ...corev1.Taint) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec:       corev1.NodeSpec{Taints: taints},
	}
}

func config(name string, spec podtracev1alpha1.TracerConfigSpec) podtracev1alpha1.TracerConfig {
	return podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       spec,
	}
}

func TestNodeTargetedByNodeSelector(t *testing.T) {
	cases := []struct {
		name     string
		selector map[string]string
		labels   map[string]string
		want     bool
	}{
		{"empty selector matches every node", nil, map[string]string{"pool": "a"}, true},
		{"single label matches", map[string]string{"pool": "a"}, map[string]string{"pool": "a"}, true},
		{"single label mismatches", map[string]string{"pool": "a"}, map[string]string{"pool": "b"}, false},
		{"missing label", map[string]string{"pool": "a"}, nil, false},
		{"all labels must match", map[string]string{"pool": "a", "arch": "arm64"}, map[string]string{"pool": "a"}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tc := config("c", podtracev1alpha1.TracerConfigSpec{NodeSelector: tt.selector})
			n := node("n1", tt.labels)
			if got := NodeTargetedBy(&n, &tc); got != tt.want {
				t.Errorf("NodeTargetedBy = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNodeTargetedByRequiredAffinity(t *testing.T) {
	requireIn := func(key string, values ...string) *corev1.Affinity {
		return &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchExpressions: []corev1.NodeSelectorRequirement{{
						Key:      key,
						Operator: corev1.NodeSelectorOpIn,
						Values:   values,
					}},
				}},
			},
		}}
	}

	tc := config("c", podtracev1alpha1.TracerConfigSpec{Affinity: requireIn("pool", "a", "b")})
	for _, tt := range []struct {
		labels map[string]string
		want   bool
	}{
		{map[string]string{"pool": "a"}, true},
		{map[string]string{"pool": "b"}, true},
		{map[string]string{"pool": "c"}, false},
		{nil, false},
	} {
		n := node("n1", tt.labels)
		if got := NodeTargetedBy(&n, &tc); got != tt.want {
			t.Errorf("labels %v: NodeTargetedBy = %v, want %v", tt.labels, got, tt.want)
		}
	}
}

func TestNodeTargetedByAffinityTermsAreOred(t *testing.T) {
	tc := config("c", podtracev1alpha1.TracerConfigSpec{
		Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{MatchExpressions: []corev1.NodeSelectorRequirement{{
						Key: "pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"a"},
					}}},
					{MatchExpressions: []corev1.NodeSelectorRequirement{{
						Key: "tier", Operator: corev1.NodeSelectorOpExists,
					}}},
				},
			},
		}},
	})

	matchesSecondTerm := node("n1", map[string]string{"tier": "gold"})
	if !NodeTargetedBy(&matchesSecondTerm, &tc) {
		t.Error("a node matching only the second term must be targeted; terms are OR'd")
	}
	matchesNeither := node("n2", map[string]string{"pool": "z"})
	if NodeTargetedBy(&matchesNeither, &tc) {
		t.Error("a node matching no term must not be targeted")
	}
}

func TestNodeTargetedByRespectsTaints(t *testing.T) {
	tainted := node("n1", nil, corev1.Taint{
		Key: "dedicated", Value: "db", Effect: corev1.TaintEffectNoSchedule,
	})

	untolerated := config("c", podtracev1alpha1.TracerConfigSpec{})
	if NodeTargetedBy(&tainted, &untolerated) {
		t.Error("a NoSchedule taint the fleet does not tolerate must exclude the node")
	}

	tolerated := config("c", podtracev1alpha1.TracerConfigSpec{
		Tolerations: []corev1.Toleration{{
			Key: "dedicated", Operator: corev1.TolerationOpEqual,
			Value: "db", Effect: corev1.TaintEffectNoSchedule,
		}},
	})
	if !NodeTargetedBy(&tainted, &tolerated) {
		t.Error("a tolerated taint must not exclude the node")
	}
}

func TestNodeTargetedByIgnoresPreferNoSchedule(t *testing.T) {
	n := node("n1", nil, corev1.Taint{
		Key: "spot", Effect: corev1.TaintEffectPreferNoSchedule,
	})
	tc := config("c", podtracev1alpha1.TracerConfigSpec{})
	if !NodeTargetedBy(&n, &tc) {
		t.Error("PreferNoSchedule never blocks admission, so it must not exclude the node")
	}
}

func TestNodeTargetedByToleratesDaemonSetImplicitTaints(t *testing.T) {
	tc := config("c", podtracev1alpha1.TracerConfigSpec{})
	cases := []struct {
		name  string
		taint corev1.Taint
	}{
		{"cordoned", corev1.Taint{
			Key: "node.kubernetes.io/unschedulable", Effect: corev1.TaintEffectNoSchedule,
		}},
		{"not-ready NoSchedule from TaintNodesByCondition", corev1.Taint{
			Key: "node.kubernetes.io/not-ready", Effect: corev1.TaintEffectNoSchedule,
		}},
		{"not-ready NoExecute from the node lifecycle controller", corev1.Taint{
			Key: "node.kubernetes.io/not-ready", Effect: corev1.TaintEffectNoExecute,
		}},
		{"unreachable NoSchedule", corev1.Taint{
			Key: "node.kubernetes.io/unreachable", Effect: corev1.TaintEffectNoSchedule,
		}},
		{"memory pressure", corev1.Taint{
			Key: "node.kubernetes.io/memory-pressure", Effect: corev1.TaintEffectNoSchedule,
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			n := node("n1", nil, tt.taint)
			if !NodeTargetedBy(&n, &tc) {
				t.Errorf("the DaemonSet controller tolerates %s/%s implicitly, so the node still belongs to the fleet",
					tt.taint.Key, tt.taint.Effect)
			}
		})
	}
}

func TestComputePartitionDisjointFleets(t *testing.T) {
	configs := []podtracev1alpha1.TracerConfig{
		config("pool-a", podtracev1alpha1.TracerConfigSpec{NodeSelector: map[string]string{"pool": "a"}}),
		config("pool-b", podtracev1alpha1.TracerConfigSpec{NodeSelector: map[string]string{"pool": "b"}}),
	}
	nodes := []corev1.Node{
		node("a1", map[string]string{"pool": "a"}),
		node("a2", map[string]string{"pool": "a"}),
		node("b1", map[string]string{"pool": "b"}),
		node("unclaimed", map[string]string{"pool": "c"}),
	}

	p := ComputePartition(configs, nodes)

	if got := len(p.Matched["pool-a"]); got != 2 {
		t.Errorf("pool-a matched %d nodes, want 2", got)
	}
	if got := len(p.Matched["pool-b"]); got != 1 {
		t.Errorf("pool-b matched %d nodes, want 1", got)
	}
	if len(p.Contested["pool-a"]) != 0 || len(p.Contested["pool-b"]) != 0 {
		t.Errorf("disjoint fleets must contest nothing, got %+v", p.Contested)
	}
	if len(p.Rivals) != 0 {
		t.Errorf("disjoint fleets must have no rivals, got %+v", p.Rivals)
	}
	if _, claimed := p.Winner["unclaimed"]; claimed {
		t.Error("a node no fleet selects must have no winner")
	}
	if msg := p.ConflictMessage("pool-a"); msg != "" {
		t.Errorf("uncontested config must produce no conflict message, got %q", msg)
	}
}

func TestComputePartitionOverlapIsSymmetric(t *testing.T) {
	configs := []podtracev1alpha1.TracerConfig{
		config("by-pool", podtracev1alpha1.TracerConfigSpec{NodeSelector: map[string]string{"pool": "a"}}),
		config("by-zone", podtracev1alpha1.TracerConfigSpec{NodeSelector: map[string]string{"zone": "eu-1"}}),
	}
	nodes := []corev1.Node{
		node("both", map[string]string{"pool": "a", "zone": "eu-1"}),
		node("pool-only", map[string]string{"pool": "a"}),
	}

	p := ComputePartition(configs, nodes)

	for _, name := range []string{"by-pool", "by-zone"} {
		if got := p.Contested[name]; len(got) != 1 || got[0] != "both" {
			t.Errorf("%s contested = %v, want [both]", name, got)
		}
		if msg := p.ConflictMessage(name); !strings.Contains(msg, "both") {
			t.Errorf("%s conflict message must name the contested node, got %q", name, msg)
		}
	}
	if got := p.Rivals["by-pool"]; len(got) != 1 || got[0] != "by-zone" {
		t.Errorf("by-pool rivals = %v, want [by-zone]", got)
	}
}

func TestComputePartitionWinnerByPriority(t *testing.T) {
	low := config("low", podtracev1alpha1.TracerConfigSpec{Priority: 1})
	high := config("high", podtracev1alpha1.TracerConfigSpec{Priority: 10})
	nodes := []corev1.Node{node("n1", nil)}

	p := ComputePartition([]podtracev1alpha1.TracerConfig{low, high}, nodes)

	if got := p.Winner["n1"]; got != "high" {
		t.Errorf("winner = %q, want high", got)
	}
	if msg := p.ConflictMessage("low"); !strings.Contains(msg, "outranked on all of them") {
		t.Errorf("loser message = %q, want it to say it was outranked", msg)
	}
	if msg := p.ConflictMessage("high"); !strings.Contains(msg, "highest priority on all of them") {
		t.Errorf("winner message = %q, want it to say it has highest priority", msg)
	}
}

func TestOutranksTieBreaks(t *testing.T) {
	older := metav1.NewTime(time.Unix(1000, 0))
	newer := metav1.NewTime(time.Unix(2000, 0))

	byAge := func(name string, ts metav1.Time) *podtracev1alpha1.TracerConfig {
		return &podtracev1alpha1.TracerConfig{
			ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: ts},
		}
	}

	if !Outranks(byAge("b", older), byAge("a", newer)) {
		t.Error("equal priority must break the tie on the older creationTimestamp, not the name")
	}
	if !Outranks(byAge("a", older), byAge("b", older)) {
		t.Error("equal priority and equal age must break the tie on the lexicographically smaller name")
	}
	if Outranks(byAge("b", older), byAge("a", older)) {
		t.Error("Outranks must be antisymmetric")
	}
}

func TestConflictMessageTruncatesNodeList(t *testing.T) {
	var configs []podtracev1alpha1.TracerConfig
	for _, name := range []string{"one", "two"} {
		configs = append(configs, config(name, podtracev1alpha1.TracerConfigSpec{}))
	}
	var nodes []corev1.Node
	for _, name := range []string{"n1", "n2", "n3", "n4", "n5", "n6", "n7"} {
		nodes = append(nodes, node(name, nil))
	}

	msg := ComputePartition(configs, nodes).ConflictMessage("one")

	if !strings.Contains(msg, "(+2 more)") {
		t.Errorf("message must summarise the tail beyond %d nodes, got %q", maxReportedContestedNodes, msg)
	}
	if strings.Contains(msg, "n7") {
		t.Errorf("message must not spell out every node, got %q", msg)
	}
}

func TestComputePartitionEmptyCluster(t *testing.T) {
	p := ComputePartition(nil, nil)
	if len(p.Matched) != 0 || len(p.Winner) != 0 {
		t.Errorf("empty inputs must produce an empty partition, got %+v", p)
	}
	if msg := p.ConflictMessage("absent"); msg != "" {
		t.Errorf("unknown config must produce no message, got %q", msg)
	}
}
