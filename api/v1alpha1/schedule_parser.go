package v1alpha1

import (
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
)

var scheduleParser = cron.NewParser(
	cron.SecondOptional |
		cron.Minute |
		cron.Hour |
		cron.Dom |
		cron.Month |
		cron.Dow |
		cron.Descriptor,
)

func ParseSchedule(expr string) (cron.Schedule, error) {
	sched, err := scheduleParser.Parse(expr)
	if err != nil {
		return nil, err
	}
	if sched.Next(time.Now()).IsZero() {
		return nil, fmt.Errorf("schedule %q never fires", expr)
	}
	return sched, nil
}
