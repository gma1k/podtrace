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
	low := config("low", podtracev1alpha1.TracerConfigSpec{FleetPriority: 1})
	high := config("high", podtracev1alpha1.TracerConfigSpec{FleetPriority: 10})
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

func TestOutranksPrefersTargetedFleetOverClusterWide(t *testing.T) {
	catchAll := config("default", podtracev1alpha1.TracerConfigSpec{})
	targeted := config("regulated", podtracev1alpha1.TracerConfigSpec{
		NodeSelector: map[string]string{"pool": "regulated"},
	})

	if !Outranks(&targeted, &catchAll) {
		t.Error("a config with a nodeSelector must beat a cluster-wide one at equal priority, or the stock default wins every node alphabetically")
	}
	if Outranks(&catchAll, &targeted) {
		t.Error("Outranks must be antisymmetric across the specificity tie-break")
	}
}

func TestOutranksPriorityStillBeatsSpecificity(t *testing.T) {
	catchAll := config("default", podtracev1alpha1.TracerConfigSpec{FleetPriority: 100})
	targeted := config("regulated", podtracev1alpha1.TracerConfigSpec{
		NodeSelector: map[string]string{"pool": "regulated"},
	})

	if !Outranks(&catchAll, &targeted) {
		t.Error("an explicit spec.fleetPriority must override the specificity heuristic")
	}
}

func TestComputePartitionTargetedFleetWinsItsOwnNode(t *testing.T) {
	configs := []podtracev1alpha1.TracerConfig{
		config("default", podtracev1alpha1.TracerConfigSpec{}),
		config("regulated", podtracev1alpha1.TracerConfigSpec{
			NodeSelector: map[string]string{"pool": "regulated"},
		}),
	}
	nodes := []corev1.Node{
		node("n-regulated", map[string]string{"pool": "regulated"}),
		node("n-plain", nil),
	}

	p := ComputePartition(configs, nodes)

	if got := p.Winner["n-regulated"]; got != "regulated" {
		t.Errorf("winner for the targeted node = %q, want regulated", got)
	}
	if got := p.Winner["n-plain"]; got != "default" {
		t.Errorf("winner for the untargeted node = %q, want default", got)
	}
}

func affinityWith(terms ...corev1.NodeSelectorTerm) *corev1.Affinity {
	return &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: terms},
	}}
}

func termWithExpressions(reqs ...corev1.NodeSelectorRequirement) corev1.NodeSelectorTerm {
	return corev1.NodeSelectorTerm{MatchExpressions: reqs}
}

func TestNodeTargetedByAffinityOperators(t *testing.T) {
	cases := []struct {
		name   string
		req    corev1.NodeSelectorRequirement
		labels map[string]string
		want   bool
	}{
		{"In matches", corev1.NodeSelectorRequirement{Key: "pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"a"}}, map[string]string{"pool": "a"}, true},
		{"In misses", corev1.NodeSelectorRequirement{Key: "pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"a"}}, map[string]string{"pool": "b"}, false},
		{"NotIn excludes listed", corev1.NodeSelectorRequirement{Key: "pool", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"a"}}, map[string]string{"pool": "a"}, false},
		{"NotIn admits unlisted", corev1.NodeSelectorRequirement{Key: "pool", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"a"}}, map[string]string{"pool": "b"}, true},
		{"NotIn admits absent label", corev1.NodeSelectorRequirement{Key: "pool", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"a"}}, nil, true},
		{"Exists with label", corev1.NodeSelectorRequirement{Key: "pool", Operator: corev1.NodeSelectorOpExists}, map[string]string{"pool": ""}, true},
		{"Exists without label", corev1.NodeSelectorRequirement{Key: "pool", Operator: corev1.NodeSelectorOpExists}, nil, false},
		{"DoesNotExist without label", corev1.NodeSelectorRequirement{Key: "pool", Operator: corev1.NodeSelectorOpDoesNotExist}, nil, true},
		{"DoesNotExist with label", corev1.NodeSelectorRequirement{Key: "pool", Operator: corev1.NodeSelectorOpDoesNotExist}, map[string]string{"pool": "a"}, false},
		{"Gt above", corev1.NodeSelectorRequirement{Key: "cores", Operator: corev1.NodeSelectorOpGt, Values: []string{"4"}}, map[string]string{"cores": "8"}, true},
		{"Gt equal", corev1.NodeSelectorRequirement{Key: "cores", Operator: corev1.NodeSelectorOpGt, Values: []string{"4"}}, map[string]string{"cores": "4"}, false},
		{"Lt below", corev1.NodeSelectorRequirement{Key: "cores", Operator: corev1.NodeSelectorOpLt, Values: []string{"4"}}, map[string]string{"cores": "2"}, true},
		{"Lt equal", corev1.NodeSelectorRequirement{Key: "cores", Operator: corev1.NodeSelectorOpLt, Values: []string{"4"}}, map[string]string{"cores": "4"}, false},
		{"Gt on non-numeric label", corev1.NodeSelectorRequirement{Key: "cores", Operator: corev1.NodeSelectorOpGt, Values: []string{"4"}}, map[string]string{"cores": "many"}, false},
		{"Gt with non-numeric bound", corev1.NodeSelectorRequirement{Key: "cores", Operator: corev1.NodeSelectorOpGt, Values: []string{"lots"}}, map[string]string{"cores": "8"}, false},
		{"Gt with absent label", corev1.NodeSelectorRequirement{Key: "cores", Operator: corev1.NodeSelectorOpGt, Values: []string{"4"}}, nil, false},
		{"Gt with two bounds is malformed", corev1.NodeSelectorRequirement{Key: "cores", Operator: corev1.NodeSelectorOpGt, Values: []string{"4", "8"}}, map[string]string{"cores": "16"}, false},
		{"unknown operator", corev1.NodeSelectorRequirement{Key: "pool", Operator: corev1.NodeSelectorOperator("Bogus"), Values: []string{"a"}}, map[string]string{"pool": "a"}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tc := config("c", podtracev1alpha1.TracerConfigSpec{Affinity: affinityWith(termWithExpressions(tt.req))})
			n := node("n1", tt.labels)
			if got := NodeTargetedBy(&n, &tc); got != tt.want {
				t.Errorf("NodeTargetedBy = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNodeTargetedByMatchFields(t *testing.T) {
	cases := []struct {
		name     string
		req      corev1.NodeSelectorRequirement
		nodeName string
		want     bool
	}{
		{"metadata.name In matches", corev1.NodeSelectorRequirement{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{"n1"}}, "n1", true},
		{"metadata.name In misses", corev1.NodeSelectorRequirement{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{"n1"}}, "n2", false},
		{"metadata.name NotIn", corev1.NodeSelectorRequirement{Key: "metadata.name", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"n1"}}, "n2", true},
		{"unsupported field key", corev1.NodeSelectorRequirement{Key: "spec.unschedulable", Operator: corev1.NodeSelectorOpIn, Values: []string{"true"}}, "n1", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tc := config("c", podtracev1alpha1.TracerConfigSpec{
				Affinity: affinityWith(corev1.NodeSelectorTerm{MatchFields: []corev1.NodeSelectorRequirement{tt.req}}),
			})
			n := node(tt.nodeName, nil)
			if got := NodeTargetedBy(&n, &tc); got != tt.want {
				t.Errorf("NodeTargetedBy = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNodeTargetedByEmptyAffinityShapes(t *testing.T) {
	n := node("n1", map[string]string{"pool": "a"})

	empty := config("c", podtracev1alpha1.TracerConfigSpec{
		Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{}},
	})
	if !NodeTargetedBy(&n, &empty) {
		t.Error("nodeAffinity with no required clause must not constrain the fleet")
	}

	noTerms := config("c", podtracev1alpha1.TracerConfigSpec{Affinity: affinityWith()})
	if !NodeTargetedBy(&n, &noTerms) {
		t.Error("a required clause with zero terms must not constrain the fleet")
	}

	emptyTerm := config("c", podtracev1alpha1.TracerConfigSpec{Affinity: affinityWith(corev1.NodeSelectorTerm{})})
	if NodeTargetedBy(&n, &emptyTerm) {
		t.Error("a term with neither expressions nor fields matches nothing")
	}

	onlyPreferred := config("c", podtracev1alpha1.TracerConfigSpec{
		Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{{
				Weight:     10,
				Preference: termWithExpressions(corev1.NodeSelectorRequirement{Key: "pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"zzz"}}),
			}},
		}},
	})
	if !NodeTargetedBy(&n, &onlyPreferred) {
		t.Error("preferred affinity changes scoring, not admissibility, so it must not exclude a node")
	}
}

func TestNodeTargetedByAllRequirementsInATermMustHold(t *testing.T) {
	tc := config("c", podtracev1alpha1.TracerConfigSpec{
		Affinity: affinityWith(termWithExpressions(
			corev1.NodeSelectorRequirement{Key: "pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"a"}},
			corev1.NodeSelectorRequirement{Key: "tier", Operator: corev1.NodeSelectorOpExists},
		)),
	})

	both := node("n1", map[string]string{"pool": "a", "tier": "gold"})
	if !NodeTargetedBy(&both, &tc) {
		t.Error("a node satisfying every requirement in the term must be targeted")
	}
	partial := node("n2", map[string]string{"pool": "a"})
	if NodeTargetedBy(&partial, &tc) {
		t.Error("requirements within a term are AND'd; a partial match must not be targeted")
	}
}

func TestNodeTargetedByCombinesSelectorAffinityAndTaints(t *testing.T) {
	tc := config("c", podtracev1alpha1.TracerConfigSpec{
		NodeSelector: map[string]string{"pool": "a"},
		Affinity:     affinityWith(termWithExpressions(corev1.NodeSelectorRequirement{Key: "tier", Operator: corev1.NodeSelectorOpExists})),
	})

	ok := node("n1", map[string]string{"pool": "a", "tier": "gold"})
	if !NodeTargetedBy(&ok, &tc) {
		t.Error("selector and affinity both satisfied must target the node")
	}
	selectorFails := node("n2", map[string]string{"pool": "b", "tier": "gold"})
	if NodeTargetedBy(&selectorFails, &tc) {
		t.Error("nodeSelector must still gate even when affinity matches")
	}
	taintBlocks := node("n3", map[string]string{"pool": "a", "tier": "gold"},
		corev1.Taint{Key: "dedicated", Value: "db", Effect: corev1.TaintEffectNoExecute})
	if NodeTargetedBy(&taintBlocks, &tc) {
		t.Error("an untolerated NoExecute taint must exclude the node")
	}
}

func TestIsClusterWide(t *testing.T) {
	cases := []struct {
		name string
		spec podtracev1alpha1.TracerConfigSpec
		want bool
	}{
		{"bare spec", podtracev1alpha1.TracerConfigSpec{}, true},
		{"nodeSelector narrows", podtracev1alpha1.TracerConfigSpec{NodeSelector: map[string]string{"pool": "a"}}, false},
		{"required affinity narrows", podtracev1alpha1.TracerConfigSpec{
			Affinity: affinityWith(termWithExpressions(corev1.NodeSelectorRequirement{Key: "pool", Operator: corev1.NodeSelectorOpExists})),
		}, false},
		{"empty affinity does not narrow", podtracev1alpha1.TracerConfigSpec{Affinity: &corev1.Affinity{}}, true},
		{"required clause with no terms does not narrow", podtracev1alpha1.TracerConfigSpec{Affinity: affinityWith()}, true},
		{"tolerations widen, never narrow", podtracev1alpha1.TracerConfigSpec{
			Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
		}, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsClusterWide(&tt.spec); got != tt.want {
				t.Errorf("IsClusterWide = %v, want %v", got, tt.want)
			}
		})
	}
}
