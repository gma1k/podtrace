package v1alpha1

import (
	"strings"
	"testing"
)

func TestParseSchedule_RefusesScheduleThatNeverFires(t *testing.T) {
	for _, expr := range []string{"0 0 30 2 *", "0 0 31 4 *", "0 0 0 31 11 *"} {
		_, err := ParseSchedule(expr)
		if err == nil || !strings.Contains(err.Error(), "never fires") {
			t.Errorf("ParseSchedule(%q) err = %v, want a never-fires error", expr, err)
		}
	}
}

func TestParseSchedule_AcceptsRareButRealSchedule(t *testing.T) {
	for _, expr := range []string{"0 0 29 2 *", "0 0 31 12 *", "@yearly"} {
		if _, err := ParseSchedule(expr); err != nil {
			t.Errorf("ParseSchedule(%q) err = %v, want nil", expr, err)
		}
	}
}
