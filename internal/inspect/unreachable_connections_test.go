package inspect

import (
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

func dualStackConnections(ok, failed, unreachable float64) []*dto.MetricFamily {
	return []*dto.MetricFamily{
		counterFamily(familyConnections,
			counter(ok, workloadLabels(label("transport", "tcp"), label("outcome", "ok"))...),
			counter(failed, workloadLabels(label("transport", "tcp"), label("outcome", "error"))...),
			counter(unreachable, workloadLabels(label("transport", "tcp"), label("outcome", "unreachable"))...),
		),
	}
}

func TestADualStackFallbackIsNotAConnectionFailure(t *testing.T) {
	got := evalOnce(t, connectionFailureRateRule(), nil, dualStackConnections(100, 0, 800), time.Minute)
	if len(got) != 0 {
		t.Errorf("fired on %v.\n\nEvery request tried eight IPv6 addresses the pod has no "+
			"route for, then succeeded over IPv4. Scored as failures that is 89%%; the "+
			"workload is healthy and nothing it calls is failing.", got)
	}
}

func TestUnreachableAttemptsDoNotDiluteRealFailures(t *testing.T) {
	got := evalOnce(t, connectionFailureRateRule(), nil, dualStackConnections(50, 50, 900), time.Minute)
	if len(got) != 1 {
		t.Fatalf("got %d issues, want 1 for half of all real attempts failing", len(got))
	}
	if !strings.Contains(got[0].Message, "50.0%") {
		t.Errorf("message %q does not read 50%%: the 900 unreachable attempts must stay out "+
			"of the denominator too, or they hide a failing dependency", got[0].Message)
	}
}

func TestTheRuleQueryExcludesUnreachableAttempts(t *testing.T) {
	if q := connectionFailureRateRule().Query; !strings.Contains(q, `outcome!="unreachable"`) {
		t.Errorf("the documented PromQL does not exclude unreachable attempts, so it would "+
			"disagree with what the rule evaluates:\n%s", q)
	}
}
