package alerting

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type Sender interface {
	Send(ctx context.Context, alert *Alert) error
	Name() string
}

type RetrySender struct {
	sender      Sender
	maxRetries  int
	backoffBase time.Duration
}

func NewRetrySender(sender Sender, maxRetries int, backoffBase time.Duration) *RetrySender {
	return &RetrySender{
		sender:      sender,
		maxRetries:  maxRetries,
		backoffBase: backoffBase,
	}
}

const maxAlertBackoff = 30 * time.Second

// cappedBackoff returns base * 2^(attempt-1) capped at maxAlertBackoff.
// attempt is 1-based.
func cappedBackoff(base time.Duration, attempt int) time.Duration {
	backoff := base
	for i := 1; i < attempt; i++ {
		if backoff >= maxAlertBackoff {
			return maxAlertBackoff
		}
		backoff *= 2
	}
	if backoff <= 0 || backoff > maxAlertBackoff {
		return maxAlertBackoff
	}
	return backoff
}

func (rs *RetrySender) Send(ctx context.Context, alert *Alert) error {
	if alert == nil {
		return fmt.Errorf("alert is nil")
	}
	if err := alert.Validate(); err != nil {
		return fmt.Errorf("invalid alert: %w", err)
	}
	alert.Sanitize()
	var lastErr error
	for attempt := 0; attempt <= rs.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := cappedBackoff(rs.backoffBase, attempt)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		err := rs.sender.Send(ctx, alert)
		if err == nil {
			return nil
		}
		lastErr = err
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	return fmt.Errorf("failed after %d attempts: %w", rs.maxRetries+1, lastErr)
}

func (rs *RetrySender) Name() string {
	return rs.sender.Name()
}
