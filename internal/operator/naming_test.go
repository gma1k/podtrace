package operator

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"
)

// TestSessionJobName_Properties locks in the Job-name contract the
// reconciler relies on for fan-out idempotency:
//
//  1. Same (sessionUID, node) → same Job name on every call.
//  2. Different (sessionUID, node) pairs → different Job names.
//  3. Output is a valid DNS-1123 label (len <= 63, starts and ends with
//     [a-z0-9], only [a-z0-9-] in between).
//  4. Weird node names (dots, colons, uppercase) do not leak into the
//     result.
func TestSessionJobName_Properties(t *testing.T) {
	cases := []struct {
		name    string
		uid     types.UID
		node    string
		mustHave string
	}{
		{"simple", "abcdef1234567890", "ip-10-0-1-4", "pts-abcdef123456"},
		{"dotted-fqdn", "abcdef1234567890", "node-1.prod.example.com", "pts-abcdef123456"},
		{"uppercase", "abcdef1234567890", "Node-Upper", "pts-abcdef123456"},
		{"short-uid", "ab12", "node-a", "pts-ab12"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			name1 := SessionJobName(tc.uid, tc.node)
			name2 := SessionJobName(tc.uid, tc.node)
			if name1 != name2 {
				t.Fatalf("non-deterministic: %q vs %q", name1, name2)
			}
			if !strings.HasPrefix(name1, tc.mustHave) {
				t.Errorf("expected prefix %q, got %q", tc.mustHave, name1)
			}
			if len(name1) > 63 {
				t.Errorf("exceeds DNS-1123 length: %d chars", len(name1))
			}
			if !isDNS1123Label(name1) {
				t.Errorf("not a valid DNS-1123 label: %q", name1)
			}
		})
	}

	// Distinct (uid, node) pairs must produce distinct names.
	a := SessionJobName("uid-aaa", "node-a")
	b := SessionJobName("uid-aaa", "node-b")
	c := SessionJobName("uid-bbb", "node-a")
	if a == b || a == c || b == c {
		t.Errorf("collision: %s %s %s", a, b, c)
	}
}

func TestExporterBundleName_Properties(t *testing.T) {
	n := ExporterBundleName("abcdef12345678")
	if !strings.HasPrefix(n, "pt-bundle-") {
		t.Errorf("missing prefix: %q", n)
	}
	if len(n) > 63 {
		t.Errorf("exceeds DNS-1123 length: %d chars", len(n))
	}
	if !isDNS1123Label(n) {
		t.Errorf("not a valid DNS-1123 label: %q", n)
	}
	if ExporterBundleName("aaa") == ExporterBundleName("bbb") {
		t.Error("distinct UIDs collided")
	}
}

func TestSanitiseDNS(t *testing.T) {
	cases := map[string]string{
		"node-a":                "node-a",
		"Node-Upper":            "node-upper",
		"node.fqdn.example.com": "node-fqdn-example-com",
		"----trim-dashes----":   "trim-dashes",
		"":                      "node", // fallback for empty
		"!!!":                   "node",
	}
	for in, want := range cases {
		if got := sanitiseDNS(in); got != want {
			t.Errorf("sanitiseDNS(%q)=%q want %q", in, got, want)
		}
	}
}

func TestManagedObjectMeta_LabelsMerged(t *testing.T) {
	m := ManagedObjectMeta("foo", "ns", ComponentAgent, map[string]string{
		"extra": "yes",
	})
	if m.Name != "foo" || m.Namespace != "ns" {
		t.Errorf("name/namespace wrong: %+v", m)
	}
	if m.Labels[LabelManagedBy] != ManagedByValue {
		t.Error("managed-by label missing")
	}
	if m.Labels[LabelComponent] != ComponentAgent {
		t.Error("component label missing")
	}
	if m.Labels["extra"] != "yes" {
		t.Error("extra label missing")
	}
}

// isDNS1123Label is a small local check mirroring k8s DNS-1123 label rules.
// Keeping it here avoids pulling k8s.io/apimachinery/pkg/util/validation
// into this test file.
func isDNS1123Label(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' && i != 0 && i != len(s)-1:
		default:
			return false
		}
	}
	return true
}
