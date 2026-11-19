package spanattributes

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func attributeMap(ev *events.Event) map[string]string {
	out := map[string]string{}
	for _, kv := range Protocol(ev) {
		out[string(kv.Key)] = kv.Value.AsString()
	}
	return out
}

func TestProtocolAttributesPerEventType(t *testing.T) {
	cases := []struct {
		name string
		ev   *events.Event
		want map[string]string
	}{
		{"redis command", &events.Event{Type: events.EventRedisCmd, Details: "GET"},
			map[string]string{"db.system.name": "redis", "db.operation.name": "GET"}},
		{"redis command padded by the probe buffer", &events.Event{Type: events.EventRedisCmd, Details: "SET key\x00junk"},
			map[string]string{"db.system.name": "redis", "db.operation.name": "SET"}},
		{"redis without a captured command", &events.Event{Type: events.EventRedisCmd},
			map[string]string{"db.system.name": "redis"}},
		{"memcached", &events.Event{Type: events.EventMemcachedCmd, Details: "delete"},
			map[string]string{"db.system.name": "memcached", "db.operation.name": "delete"}},
		{"kafka produce", &events.Event{Type: events.EventKafkaProduce, Details: "orders"},
			map[string]string{"messaging.system": "kafka", "messaging.operation.type": "send",
				"messaging.operation.name": "produce", "messaging.destination.name": "orders"}},
		{"kafka fetch of an unknown topic", &events.Event{Type: events.EventKafkaFetch},
			map[string]string{"messaging.system": "kafka", "messaging.operation.type": "receive",
				"messaging.operation.name": "poll"}},
		{"fastcgi request", &events.Event{Type: events.EventFastCGIReq, Details: "POST", Target: "/api/submit"},
			map[string]string{"network.protocol.name": "fastcgi", "http.request.method": "POST", "url.path": "/api/submit"}},
		{"fastcgi response with control bytes", &events.Event{Type: events.EventFastCGIResp, Details: "GET /x\x01", Target: "/admin\x01tail"},
			map[string]string{"network.protocol.name": "fastcgi", "http.request.method": "GET", "url.path": "/admin"}},
		{"fastcgi without method or uri", &events.Event{Type: events.EventFastCGIResp},
			map[string]string{"network.protocol.name": "fastcgi"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := attributeMap(tc.ev)
			if len(got) != len(tc.want) {
				t.Fatalf("attributes = %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestProtocolAttributesAreEmptyForOtherEvents(t *testing.T) {
	for _, ev := range []*events.Event{nil, {Type: events.EventDNS, Details: "1.2.3.4"}, {Type: events.EventHTTPReq, Details: "GET"}} {
		if attrs := Protocol(ev); attrs != nil {
			t.Errorf("Protocol(%v) = %v, want nil", ev, attrs)
		}
	}
}

func TestTokenAndMethod(t *testing.T) {
	if got := Token("orders.v1"); got != "orders.v1" {
		t.Errorf("Token kept %q", got)
	}
	if got := Token("caf\xc3\xa9"); got != "caf" {
		t.Errorf("Token(non-ASCII) = %q", got)
	}
	if got := Method("PATCH"); got != "PATCH" {
		t.Errorf("Method kept %q", got)
	}
	if got := Method("1GET"); got != "" {
		t.Errorf("Method(1GET) = %q", got)
	}
}
