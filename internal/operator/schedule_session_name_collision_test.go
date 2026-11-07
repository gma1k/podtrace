package operator

import (
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestScheduledSessionName_LongNamesSharingAPrefixDoNotCollide(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	prefix := strings.Repeat("a", 55)
	first := scheduledSessionName(prefix+"-one", at)
	second := scheduledSessionName(prefix+"-two", at)

	if first == second {
		t.Fatalf("schedules %q and %q both produce session %q", prefix+"-one", prefix+"-two", first)
	}
	for _, name := range []string{first, second} {
		if len(name) > 63 || len(validation.IsDNS1123Subdomain(name)) > 0 || !strings.HasSuffix(name, "-1700000000") {
			t.Errorf("session name %q must be a valid name of at most 63 characters ending in the run time", name)
		}
	}
}

func TestTriggeredSessionName_LongNamesSharingAPrefixDoNotCollide(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	prefix := strings.Repeat("a", 45)
	first := triggeredSessionName(prefix+"-one", "obs", "hog", at)
	second := triggeredSessionName(prefix+"-two", "obs", "hog", at)

	if first == second {
		t.Fatalf("schedules sharing a prefix both produce triggered session %q", first)
	}
	for _, name := range []string{first, second} {
		if len(name) > 63 || len(validation.IsDNS1123Subdomain(name)) > 0 {
			t.Errorf("session name %q must be a valid name of at most 63 characters", name)
		}
	}
}

func TestSessionNames_ShortScheduleNamesAreUnchanged(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	if got := scheduledSessionName("nightly", at); got != "nightly-1700000000" {
		t.Errorf("scheduledSessionName = %q, want the plain schedule-runtime form", got)
	}
	got := triggeredSessionName("on-alert", "obs", "hog", at)
	if !strings.HasPrefix(got, "on-alert-") || strings.Count(got, "-") != 3 {
		t.Errorf("triggeredSessionName = %q, want the schedule name, pod hash and alert time only", got)
	}
}
