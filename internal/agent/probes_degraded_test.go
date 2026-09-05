package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func readyzStatus(t *testing.T, s *ProbeServer) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	return rec.Code, rec.Body.String()
}

func TestADegradedAgentIsNotReady(t *testing.T) {
	s := NewProbeServer(":0", 0)
	s.MarkReady()

	if code, _ := readyzStatus(t, s); code != http.StatusOK {
		t.Fatalf("a healthy agent reported %d, want 200", code)
	}

	s.MarkDegraded("collection_failed")

	code, body := readyzStatus(t, s)
	if code != http.StatusServiceUnavailable {
		t.Errorf("/readyz returned %d after the backend failed to load, want 503. The agent "+
			"still starts, still serves its endpoints and still reconciles, so with readiness "+
			"unaffected the pod reports 1/1, rollout status succeeds and a Helm --wait returns "+
			"while nothing is being captured", code)
	}
	if body != "degraded: collection_failed" {
		t.Errorf("body = %q; the reason has to travel with the failure or an operator sees only "+
			"a bare 503", body)
	}
}

func TestIsReadyAgreesWithReadyz(t *testing.T) {
	s := NewProbeServer(":0", 0)
	s.MarkReady()
	if !s.IsReady() {
		t.Fatal("a healthy agent reported not ready")
	}

	s.MarkDegraded("attach_failed")
	if s.IsReady() {
		t.Error("IsReady disagrees with /readyz. The status writer builds the CR's per-node " +
			"Ready from IsReady, so a disagreement means the pod and the CR tell an operator " +
			"different stories about the same agent")
	}
}

func TestAnEmptyReasonStillMarksDegraded(t *testing.T) {
	s := NewProbeServer(":0", 0)
	s.MarkReady()
	s.MarkDegraded("")

	code, body := readyzStatus(t, s)
	if code != http.StatusServiceUnavailable {
		t.Errorf("/readyz returned %d for a degraded agent with no reason, want 503", code)
	}
	if body != "degraded: unknown" {
		t.Errorf("body = %q, want a placeholder reason rather than an empty one", body)
	}
}

func TestDegradationOutranksNotYetReady(t *testing.T) {
	s := NewProbeServer(":0", 0)
	s.MarkDegraded("collection_failed")

	_, body := readyzStatus(t, s)
	if body == "not ready" {
		t.Error("a degraded agent that has not finished syncing reports plain \"not ready\", " +
			"which reads as a transient startup state and invites waiting it out forever")
	}
}

func TestDegradedReasonIsEmptyWhenHealthy(t *testing.T) {
	s := NewProbeServer(":0", 0)
	if got := s.DegradedReason(); got != "" {
		t.Errorf("DegradedReason = %q on a fresh server, want empty", got)
	}
}
