package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func hungAPIServer(t *testing.T) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(ctx context.Context, _ client.Client, _ string, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
				<-ctx.Done()
				return ctx.Err()
			},
		}).Build()
}

func TestAHungAPIServerDoesNotStopTheHeartbeat(t *testing.T) {
	router := NewRouter(nil)
	router.Publish([]CRRule{{Key: CRKey{Namespace: "ns", Name: "pt"}}})
	var beats atomic.Int32
	w := &StatusWriter{
		Client:    hungAPIServer(t),
		NodeName:  "n",
		Interval:  40 * time.Millisecond,
		Router:    router,
		Ready:     func() bool { return true },
		Heartbeat: func() { beats.Add(1) },
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = w.Run(ctx)

	if got := beats.Load(); got < 4 {
		t.Errorf("%d heartbeats in 500ms at a 40ms interval with every status write hanging, "+
			"want at least 4; a write with no deadline stops the heartbeat and the liveness "+
			"probe restarts an agent whose capture is fine", got)
	}
}

func TestTheStallWindowCoversTheReportInterval(t *testing.T) {
	for _, tt := range []struct {
		interval, want time.Duration
	}{
		{0, 90 * time.Second},
		{10 * time.Second, 90 * time.Second},
		{30 * time.Second, 90 * time.Second},
		{60 * time.Second, 180 * time.Second},
		{5 * time.Minute, 15 * time.Minute},
	} {
		got := StallWindowFor(tt.interval)
		if got != tt.want {
			t.Errorf("StallWindowFor(%v) = %v, want %v", tt.interval, got, tt.want)
		}
		interval := tt.interval
		if interval == 0 {
			interval = DefaultStatusReportInterval
		}
		if got < 2*interval {
			t.Errorf("StallWindowFor(%v) = %v is shorter than two report intervals, the "+
				"widest gap between heartbeats; /healthz would fail on a healthy agent", tt.interval, got)
		}
	}
}

func TestASlowReportIntervalDoesNotFailHealthz(t *testing.T) {
	interval := 2 * time.Minute
	s := NewProbeServer(":0", StallWindowFor(interval))
	s.lastHeartbeat.Store(time.Now().Add(-(interval + 30*time.Second)).UnixNano())

	rec := httptest.NewRecorder()
	s.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz = %d with the last beat %v ago on a %v interval; with a fixed 90s "+
			"window every agent configured this way is restarted in a loop", rec.Code,
			interval+30*time.Second, interval)
	}
}
