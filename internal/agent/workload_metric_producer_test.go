package agent

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/workloadmetrics"
)

func TestADisabledPlaneYieldsNoProducerAtAll(t *testing.T) {
	producer := workloadMetricProducer(nil)
	if producer != nil {
		t.Fatal("a nil Sink produced a non-nil interface. An interface holding a typed nil is " +
			"not nil, so the pool's \"no producer, no pusher\" check would pass and start a " +
			"push loop with nothing to send")
	}
}

func TestAnEnabledPlaneProducesTheSurface(t *testing.T) {
	sink, err := workloadmetrics.New(prometheus.NewRegistry(), workloadmetrics.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	producer := workloadMetricProducer(sink)
	if producer == nil {
		t.Fatal("an enabled plane produced no producer")
	}
	if _, err := producer.Produce(context.Background()); err != nil {
		t.Errorf("Produce: %v", err)
	}
}
