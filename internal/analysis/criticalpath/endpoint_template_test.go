package criticalpath

import (
	"strconv"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestEndpointTemplateCollapsesIDsAndDropsQueries(t *testing.T) {
	cases := map[string]string{
		"GET /users/42":                                    "GET /users/{id}",
		"GET /users/42/orders/7?expand=items":              "GET /users/{id}/orders/{id}",
		"GET /orders/3f2b8c1e-9a4d-4e6f-8b2a-1c3d5e7f9a0b": "GET /orders/{id}",
		"GET /blobs/a3f9c2e1b7d4e8f6a1c3":                  "GET /blobs/{id}",
		"GET /search?q=secret#frag":                        "GET /search",
		"POST /grpc.health.v1.Health/Check":                "POST /grpc.health.v1.Health/Check",
		"GET /v1/catalog/authentication-service":           "GET /v1/catalog/authentication-service",
		"/api/item12/detail":                               "/api/item12/detail",
		"/api/items/99":                                    "/api/items/{id}",
		"GET http://shop.example/items/5":                  "GET http://shop.example/items/{id}",
		"":                                                 "",
	}
	for in, want := range cases {
		if got := endpointTemplate(in); got != want {
			t.Errorf("endpointTemplate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRequestsToOneRouteShareOneEndpointSummary(t *testing.T) {
	c := New()
	for id := uint64(1); id <= 3*maxEndpointSummaries; id++ {
		c.Feed(&events.Event{Type: events.EventHTTPReq, CorrelationID: id, Target: "GET /users/" + strconv.FormatUint(id, 10) + "?page=1"})
		c.Feed(finished(id, 0, 1, 0))
	}
	byEndpoint := c.Summary().ByEndpoint
	if len(byEndpoint) != 1 {
		t.Fatalf("%d endpoint summaries, want the one route: %+v", len(byEndpoint), byEndpoint[:min(3, len(byEndpoint))])
	}
	if byEndpoint[0].Endpoint != "GET /users/{id}" || byEndpoint[0].Requests != 3*maxEndpointSummaries {
		t.Fatalf("endpoint = %+v, want every request under GET /users/{id}", byEndpoint[0])
	}
	if got := c.Summary().Slowest[0].Endpoint; got == "GET /users/{id}" {
		t.Fatalf("slowest request endpoint = %q, want the concrete target kept", got)
	}
}
