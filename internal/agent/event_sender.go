package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/podtrace/podtrace/internal/alerting"
)

// alertEventSender is an alerting.Sender that records each alert as a
// Kubernetes Event on the alert's pod.
type alertEventSender struct {
	client   client.Client
	nowFn    func() time.Time
	throttle time.Duration

	mu   sync.Mutex
	last map[string]time.Time
}

func newAlertEventSender(c client.Client) *alertEventSender {
	return &alertEventSender{
		client:   c,
		nowFn:    time.Now,
		throttle: 30 * time.Second,
		last:     map[string]time.Time{},
	}
}

func (s *alertEventSender) Name() string { return "kubernetes-event" }

func (s *alertEventSender) Send(ctx context.Context, alert *alerting.Alert) error {
	now := s.nowFn()
	event := alerting.BuildAlertEvent(alert, now)
	if event == nil {
		return nil
	}
	if s.throttledDuplicate(alert, now) {
		return nil
	}
	if err := s.client.Create(ctx, event); err != nil {
		return fmt.Errorf("create alert Event for %s/%s: %w", alert.Namespace, alert.PodName, err)
	}
	return nil
}

// throttledDuplicate reports whether an identical (pod, source, severity)
// alert was emitted within the throttle window, and otherwise records this
// emission. It prunes stale keys opportunistically so the map is bounded.
func (s *alertEventSender) throttledDuplicate(alert *alerting.Alert, now time.Time) bool {
	key := alert.Namespace + "/" + alert.PodName + "|" + alert.Source + "|" + string(alert.Severity)
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.last[key]; ok && now.Sub(last) < s.throttle {
		return true
	}
	s.last[key] = now
	for k, t := range s.last {
		if now.Sub(t) > 10*s.throttle {
			delete(s.last, k)
		}
	}
	return false
}
