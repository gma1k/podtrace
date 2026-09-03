package config

import (
	"os"
	"testing"
)

func TestSplitCommaEnv(t *testing.T) {
	const key = "PODTRACE_TEST_SPLIT_COMMA"

	for _, tc := range []struct {
		name string
		set  bool
		val  string
		want []string
	}{
		{"unset", false, "", nil},
		{"empty", true, "", nil},
		{"single", true, "kube-system", []string{"kube-system"}},
		{"multiple", true, "a,b,c", []string{"a", "b", "c"}},
		{"surrounding space", true, " a , b ", []string{"a", "b"}},
		{"empty elements dropped", true, "a,,b,", []string{"a", "b"}},
		{"only separators", true, ",,,", nil},
		{"only space", true, "   ", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(key, tc.val)
			} else if _, present := os.LookupEnv(key); present {
				t.Fatalf("%s leaked from another test", key)
			}

			got := splitCommaEnv(key)
			if len(got) != len(tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("index %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
