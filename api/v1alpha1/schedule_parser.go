package v1alpha1

import "github.com/robfig/cron/v3"

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
	return scheduleParser.Parse(expr)
}