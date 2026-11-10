package alerting

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
)

type recordingSender struct {
	name string
	mu   sync.Mutex
	got  map[string]int
}

func newRecordingSender(name string) *recordingSender {
	return &recordingSender{name: name, got: map[string]int{}}
}

func (r *recordingSender) Send(_ context.Context, alert *Alert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got[alert.Namespace]++
	return nil
}

func (r *recordingSender) Name() string { return r.name }

func (r *recordingSender) count(namespace string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.got[namespace]
}

type scopedRecordingSender struct{ *recordingSender }

func (scopedRecordingSender) NamespaceScoped() bool { return true }

type dropCounter struct {
	mu      sync.Mutex
	reasons map[string]int
}

func (d *dropCounter) observe(reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.reasons == nil {
		d.reasons = map[string]int{}
	}
	d.reasons[reason]++
}

func (d *dropCounter) count(reason string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reasons[reason]
}

func storm(namespace string, n int) []*Alert {
	alerts := make([]*Alert, 0, n)
	for i := 0; i < n; i++ {
		alerts = append(alerts, &Alert{
			Severity:  SeverityCritical,
			Title:     fmt.Sprintf("OOM in pod-%d", i),
			Message:   "oom",
			Timestamp: time.Now(),
			Source:    AlertSourceOOM,
			PodName:   fmt.Sprintf("pod-%d", i),
			Namespace: namespace,
		})
	}
	return alerts
}

func limitedManager(t *testing.T, perNamespace, node int, senders ...Sender) (*Manager, *dropCounter) {
	t.Helper()
	origEnabled := config.AlertingEnabled
	t.Cleanup(func() { config.AlertingEnabled = origEnabled })
	config.AlertingEnabled = true
	t.Setenv("PODTRACE_ALERT_MIN_SEVERITY", "warning")
	drops := &dropCounter{}
	m := &Manager{
		enabled:         true,
		senders:         senders,
		deduplicator:    NewAlertDeduplicator(10 * time.Minute),
		rateLimiter:     NewNamespaceRateLimiter(perNamespace),
		nodeRateLimiter: NewRateLimiter(node),
		stopCh:          make(chan struct{}),
	}
	m.SetDropObserver(drops.observe)
	return m, drops
}

func drain(t *testing.T, m *Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestOneNamespacesAlertStormDoesNotSilenceAnother(t *testing.T) {
	external := newRecordingSender("webhook")
	m, drops := limitedManager(t, 5, 1000, external)

	for _, a := range storm("noisy", 50) {
		m.SendAlert(a)
	}
	for _, a := range storm("quiet", 3) {
		m.SendAlert(a)
	}
	drain(t, m)

	if got := external.count("noisy"); got != 5 {
		t.Errorf("noisy namespace delivered %d alerts, want its budget of 5", got)
	}
	if got := external.count("quiet"); got != 3 {
		t.Errorf("quiet namespace delivered %d alerts, want all 3 despite the noisy namespace's storm", got)
	}
	if got := drops.count(DropReasonNamespaceRateLimit); got != 45 {
		t.Errorf("namespace drops counted = %d, want 45", got)
	}
}

func TestTheNodeCeilingNeverStarvesTheEventSink(t *testing.T) {
	external := newRecordingSender("slack")
	events := scopedRecordingSender{newRecordingSender("kubernetes-event")}
	m, drops := limitedManager(t, 100, 2, external, events)

	for _, a := range storm("tenant-a", 5) {
		m.SendAlert(a)
	}
	for _, a := range storm("tenant-b", 5) {
		m.SendAlert(a)
	}
	drain(t, m)

	if got := external.count("tenant-a") + external.count("tenant-b"); got != 2 {
		t.Errorf("external receivers got %d alerts, want the node ceiling of 2", got)
	}
	if got := events.count("tenant-b"); got != 5 {
		t.Errorf("tenant-b trigger Events = %d, want 5: the flight recorder must not lose triggers to another tenant", got)
	}
	if got := events.count("tenant-a"); got != 5 {
		t.Errorf("tenant-a trigger Events = %d, want 5", got)
	}
	if got := drops.count(DropReasonNodeRateLimit); got != 8 {
		t.Errorf("node drops counted = %d, want 8", got)
	}
}

func TestANodeLimitedAlertWithNoOtherSenderIsRetriedLater(t *testing.T) {
	external := newRecordingSender("webhook")
	m, drops := limitedManager(t, 100, 0, external)

	alert := storm("tenant", 1)[0]
	m.SendAlert(alert)
	if !m.deduplicator.ShouldSend(alert) {
		t.Error("a node-limited alert kept its dedup record, so the next occurrence would be silenced")
	}
	drain(t, m)
	if got := drops.count(DropReasonNodeRateLimit); got != 1 {
		t.Errorf("node drops counted = %d, want 1", got)
	}
	if got := external.count("tenant"); got != 0 {
		t.Errorf("delivered %d alerts through an exhausted node ceiling", got)
	}
}

func TestANamespaceLimitedAlertIsForgottenByTheDeduplicator(t *testing.T) {
	external := newRecordingSender("webhook")
	m, _ := limitedManager(t, 0, 100, external)

	alert := storm("tenant", 1)[0]
	m.SendAlert(alert)
	if !m.deduplicator.ShouldSend(alert) {
		t.Error("a namespace-limited alert kept its dedup record")
	}
	drain(t, m)
}

func TestEnsureEnabledAddsTheNodeCeiling(t *testing.T) {
	m := &Manager{}
	m.EnsureEnabledWithSender(scopedRecordingSender{newRecordingSender("kubernetes-event")})
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	if m.rateLimiter == nil || m.nodeRateLimiter == nil {
		t.Fatalf("limiters not initialised: namespace=%v node=%v", m.rateLimiter, m.nodeRateLimiter)
	}
}
