package config

import "testing"

func TestNonNegativeIntEnvAcceptsZeroAsASetting(t *testing.T) {
	const key = "PODTRACE_TEST_NON_NEGATIVE_INT"
	for value, want := range map[string]int{
		"":    9,
		"0":   0,
		"12":  12,
		"-1":  9,
		"abc": 9,
	} {
		t.Setenv(key, value)
		if got := getNonNegativeIntEnvOrDefault(key, 9); got != want {
			t.Errorf("%q: got %d, want %d", value, got, want)
		}
	}
}

func TestTheContainerRowBudgetDefaultsOn(t *testing.T) {
	if WorkloadMetricsContainerRowBudget != 4096 {
		t.Errorf("default row budget = %d, want 4096", WorkloadMetricsContainerRowBudget)
	}
}
