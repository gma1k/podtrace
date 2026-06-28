package agent

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// newOTLPEventExporter builds a tracer.Exporter that ships per-event
// spans over OTLP HTTP.
func newOTLPEventExporter(cr CRKey, b *BundlePayload, opts ...sdkOption) (tracer.Exporter, error) {
	spanExporter, err := newOTLPSpanExporter(b)
	if err != nil {
		return nil, err
	}
	return newSDKEventExporter("otlp", cr, b, spanExporter, opts...)
}

// newOTLPSpanExporter wires an otlptrace HTTP client from a bundle.
// Shared by every OTLP-speaking backend (OTLP, Jaeger, DataDog, Splunk).
func newOTLPSpanExporter(b *BundlePayload) (*otlptrace.Exporter, error) {
	if b.Endpoint == "" {
		return nil, fmt.Errorf("bundle missing endpoint")
	}

	endpoint, err := normalizeOTLPEndpoint(b.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("bundle endpoint: %w", err)
	}

	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpoint),
	}
	if b.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(b.Headers) > 0 || len(b.SecretHeaders) > 0 || b.HeaderName != "" {
		headers := map[string]string{}
		for k, v := range b.Headers {
			headers[k] = v
		}
		for k, v := range b.SecretHeaders {
			headers[k] = v
		}
		if b.HeaderName != "" && len(b.Credential) > 0 {
			headers[b.HeaderName] = string(b.Credential)
		}
		opts = append(opts, otlptracehttp.WithHeaders(headers))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := otlptracehttp.NewClient(opts...)
	spanExporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("create OTLP span exporter: %w", err)
	}
	return spanExporter, nil
}

// normalizeOTLPEndpoint strips any scheme because otlptracehttp takes
// a host:port (it adds scheme based on WithInsecure). Accepts both
// "collector:4318" and "http://collector:4318" forms for user convenience.
func normalizeOTLPEndpoint(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("empty endpoint")
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		return u.Host, nil
	}
	return raw, nil
}

// eventSpanName picks a human-readable span name from the event. Keep
// it short: trace backends index span-name heavily and verbose names
// balloon cardinality.
func eventSpanName(ev *events.Event) string {
	base := eventTypeString(ev.Type)
	if ev.Target != "" {
		return base + " " + ev.Target
	}
	return base
}

func eventTypeString(t events.EventType) string {
	if s, ok := eventTypeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("event_%d", uint32(t))
}

// eventTypeNames maps the small set of EventType values we care about
// for span-name readability. Unmatched values fall back to the generic
// "event_<N>" in eventTypeString — we explicitly prefer this over
// dumping the bare int so span search queries remain legible.
var eventTypeNames = map[events.EventType]string{
	events.EventDNS:            "dns",
	events.EventConnect:        "net.connect",
	events.EventTCPSend:        "net.tcp.send",
	events.EventTCPRecv:        "net.tcp.recv",
	events.EventUDPSend:        "net.udp.send",
	events.EventUDPRecv:        "net.udp.recv",
	events.EventTCPState:       "net.tcp.state",
	events.EventTCPRetrans:     "net.tcp.retransmit",
	events.EventNetDevError:    "net.dev.error",
	events.EventWrite:          "fs.write",
	events.EventRead:           "fs.read",
	events.EventOpen:           "fs.open",
	events.EventClose:          "fs.close",
	events.EventFsync:          "fs.fsync",
	events.EventUnlink:         "fs.unlink",
	events.EventRename:         "fs.rename",
	events.EventSchedSwitch:    "cpu.sched",
	events.EventLockContention: "cpu.lock",
	events.EventPageFault:      "mem.pagefault",
	events.EventOOMKill:        "mem.oomkill",
	events.EventExec:           "proc.exec",
	events.EventFork:           "proc.fork",
	events.EventHTTPReq:        "http.req",
	events.EventHTTPResp:       "http.resp",
	events.EventHTTP3:          "http3.conn",
	events.EventDBQuery:        "db.query",
}
