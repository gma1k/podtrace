package operator

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

var frontIssue = detector.IssueRef{ID: "l7.latency_degraded", Namespace: "shop", Workload: "front"}

func grantingNamespace(name, grant string) *corev1.Namespace {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if grant != "" {
		ns.Annotations = map[string]string{podtracev1alpha1.AllowTracingFromAnnotation: grant}
	}
	return ns
}

func announcedCauses(t *testing.T, causes []detector.Cause, objects ...client.Object) string {
	t.Helper()
	c, cl := announcingCorrelator(t, interceptor.Funcs{}, append([]client.Object{frontPod()}, objects...)...)
	result := Correlation{Issues: []CorrelatedIssue{{IssueRef: frontIssue, Causes: causes}}}
	c.announce(context.Background(), result, map[detector.IssueRef]string{frontIssue: "front-0"})

	events := causeEvents(t, cl)
	if len(events) != 1 {
		t.Fatalf("%d likely-cause Events, want 1", len(events))
	}
	if got := events[0].Annotations[alerting.AnnotationLikelyCauses]; !strings.HasSuffix(events[0].Message, got) {
		t.Errorf("message %q and annotation %q must name the same causes", events[0].Message, got)
	}
	return events[0].Annotations[alerting.AnnotationLikelyCauses]
}

func paymentsCause(via ...detector.IssueRef) detector.Cause {
	return detector.Cause{IssueRef: detector.IssueRef{ID: "db.pool_saturated", Namespace: "payments", Workload: "api"}, Via: via}
}

func TestLikelyCauseEvent_NamesCauseInGrantingNamespace(t *testing.T) {
	for _, grant := range []string{"shop", podtracev1alpha1.AllowTracingFromWildcard, "other, shop"} {
		got := announcedCauses(t, []detector.Cause{paymentsCause()}, grantingNamespace("payments", grant))
		if got != "db.pool_saturated on payments/api" {
			t.Errorf("grant %q: causes = %q, want the cause named", grant, got)
		}
	}
}

func TestLikelyCauseEvent_WithholdsCauseFromNamespaceWithoutGrant(t *testing.T) {
	cases := map[string][]client.Object{
		"no grant":           {grantingNamespace("payments", "")},
		"grant to another":   {grantingNamespace("payments", "checkout")},
		"namespace not seen": nil,
	}
	for name, objects := range cases {
		t.Run(name, func(t *testing.T) {
			got := announcedCauses(t, []detector.Cause{paymentsCause()}, objects...)
			if got != withheldCause {
				t.Errorf("causes = %q, want the cause withheld", got)
			}
			if strings.Contains(got, "payments") || strings.Contains(got, "db.pool_saturated") {
				t.Errorf("causes %q leak the other namespace's issue", got)
			}
		})
	}
}

func TestLikelyCauseEvent_WithholdsCauseReachedThroughNamespaceWithoutGrant(t *testing.T) {
	hop := detector.IssueRef{ID: "l7.error_rate", Namespace: "ledger", Workload: "writer"}
	got := announcedCauses(t, []detector.Cause{paymentsCause(hop)},
		grantingNamespace("payments", "shop"), grantingNamespace("ledger", ""))
	if got != withheldCause {
		t.Errorf("causes = %q, want withheld when a hop's namespace has not granted", got)
	}
}

func TestLikelyCauseEvent_SameNamespaceCauseNeedsNoGrant(t *testing.T) {
	cause := detector.Cause{IssueRef: detector.IssueRef{ID: "db.pool_saturated", Namespace: "shop", Workload: "backend"}}
	if got := announcedCauses(t, []detector.Cause{cause}); got != "db.pool_saturated on shop/backend" {
		t.Errorf("causes = %q, want a same-namespace cause named", got)
	}
}

func TestLikelyCauseEvent_WithheldCausesAreReportedOnce(t *testing.T) {
	ledger := detector.Cause{IssueRef: detector.IssueRef{ID: "l7.error_rate", Namespace: "ledger", Workload: "writer"}}
	local := detector.Cause{IssueRef: detector.IssueRef{ID: "db.pool_saturated", Namespace: "shop", Workload: "backend"}}
	got := announcedCauses(t, []detector.Cause{paymentsCause(), local, ledger})
	if want := withheldCause + "; db.pool_saturated on shop/backend"; got != want {
		t.Errorf("causes = %q, want %q", got, want)
	}
}
