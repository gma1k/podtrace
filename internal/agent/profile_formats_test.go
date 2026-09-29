package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/pprof/profile"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/profiling"
)

func formatsProfiler() *profiling.ContinuousProfiler {
	p := profiling.NewContinuousProfiler(nil, func(cgroupID uint64) (events.K8sMetadata, bool) {
		wl := map[uint64]string{1: "checkout", 2: "cart"}[cgroupID]
		return events.K8sMetadata{Namespace: "shop", WorkloadName: wl}, wl != ""
	})
	p.IngestOnCPU(oncpu.Drained{
		Samples: []oncpu.Sample{
			{CgroupID: 1, PID: 1, Stack: []uint64{0xa, 0xb}, Count: 4, CorrelationID: 9},
			{CgroupID: 2, PID: 2, Stack: []uint64{0xc}, Count: 1},
		},
		Completions: []oncpu.Completion{{CgroupID: 1, CorrelationID: 9, LatencyNS: 2e6}},
	})
	return p
}

func getProfile(t *testing.T, p *profiling.ContinuousProfiler, query string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	profileHandler(p)(rec, httptest.NewRequest(http.MethodGet, "/profile"+query, nil))
	return rec
}

func TestTheProfileJSONNamesItsSourceAndCanBeFiltered(t *testing.T) {
	rec := getProfile(t, formatsProfiler(), "?workload=checkout")
	var body struct {
		Source   profiling.ProfileSource     `json:"source"`
		Profiles []profiling.WorkloadProfile `json:"profiles"`
		Unjoined *uint64                     `json:"unjoinedRequestSamples"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Source != profiling.SourceOnCPU || len(body.Profiles) != 1 || body.Profiles[0].Workload != "checkout" || body.Unjoined == nil {
		t.Errorf("body = %s", rec.Body.String())
	}
	if s := body.Profiles[0].SlowRequests; s == nil || s.Samples != 4 {
		t.Errorf("slow requests = %+v", s)
	}
}

func TestTheProfileServesFoldedStacks(t *testing.T) {
	rec := getProfile(t, formatsProfiler(), "?format=folded&namespace=shop")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("status %d, type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if want := "shop/cart;0xc 1\nshop/checkout;0xb;0xa 4\n"; rec.Body.String() != want {
		t.Errorf("folded = %q, want %q", rec.Body.String(), want)
	}
	slow := getProfile(t, formatsProfiler(), "?format=folded&requests=slow")
	if want := "shop/checkout;0xb;0xa 4\n"; slow.Body.String() != want {
		t.Errorf("slow folded = %q, want %q", slow.Body.String(), want)
	}
}

func TestTheProfileServesPprof(t *testing.T) {
	rec := getProfile(t, formatsProfiler(), "?format=pprof&requests=all")
	p, err := profile.ParseData(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sample) != 2 || len(p.SampleType) != 2 || !strings.Contains(rec.Header().Get("Content-Disposition"), "profile.pb.gz") {
		t.Errorf("pprof = %d samples, types %v", len(p.Sample), p.SampleType)
	}
}

func TestTheProfileRejectsWhatItCannotServe(t *testing.T) {
	for _, q := range []string{"?format=svg", "?requests=fast", "?requests=slow"} {
		if rec := getProfile(t, formatsProfiler(), q); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, rec.Code)
		}
	}
}

func TestAFilterThatMatchesNothingReturnsAnEmptyList(t *testing.T) {
	rec := getProfile(t, formatsProfiler(), "?workload=does-not-exist")
	if !strings.Contains(rec.Body.String(), `"profiles":[]`) {
		t.Errorf("body = %s; a script iterating profiles would break on null", rec.Body.String())
	}
}
