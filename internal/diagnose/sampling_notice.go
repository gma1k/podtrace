package diagnose

import (
	"time"

	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/logger"
)

// samplingNoticeInterval is how often a diagnostician that is sampling says
// so again after its first warning.
const samplingNoticeInterval = time.Minute

// logSamplingLocked tells the operator the buffer is full: a warning the
// first time, then a progress line at most once per samplingNoticeInterval.
func (d *Diagnostician) logSamplingLocked() {
	now := time.Now
	if d.now != nil {
		now = d.now
	}
	t := now()
	fields := []zap.Field{zap.Int("max_events", d.maxEvents), zap.Int("sampled_out", d.droppedEvents)}
	switch {
	case d.droppedEvents == 1:
		logger.Logger().Warn("Event buffer full; sampling events from here on, and the report will say how many it sampled out", fields...)
	case t.Sub(d.lastSamplingNotice) < samplingNoticeInterval:
		return
	default:
		logger.Logger().Info("Event buffer still sampling", fields...)
	}
	d.lastSamplingNotice = t
}
