package agent

import (
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"

	"github.com/gma1k/podtrace/internal/config"
)

func TestInspectionsThatCannotStartAreLoggedAndLeaveNoEngine(t *testing.T) {
	original := config.InspectionsEnabled
	config.InspectionsEnabled = true
	t.Cleanup(func() { config.InspectionsEnabled = original })

	var logged []string
	logger := funcr.New(func(_, args string) { logged = append(logged, args) }, funcr.Options{})
	metrics := NewMetrics()

	if engine := startInspectionEngine(metrics, stubFamilySource{}, nil, &fakeEventSink{}, logger); engine == nil {
		t.Fatal("the first engine did not start")
	}
	if engine := startInspectionEngine(metrics, stubFamilySource{}, nil, &fakeEventSink{}, logger); engine != nil {
		t.Error("an engine whose metrics could not register was returned")
	}
	found := false
	for _, l := range logged {
		found = found || strings.Contains(l, "continuous inspections unavailable")
	}
	if !found {
		t.Errorf("logged %v; the reason inspections are off was not said", logged)
	}
}
