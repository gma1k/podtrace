package tracer

import "testing"

func TestSetDropReporter_NilClears(t *testing.T) {
	tr := &Tracer{}
	tr.SetDropReporter(func(string, int) {})
	tr.SetDropReporter(nil)
	tr.reportDrop("x", 1)
}
