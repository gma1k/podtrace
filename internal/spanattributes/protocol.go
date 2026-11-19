// Package spanattributes maps the protocol detail podtrace captures for an
// event onto OpenTelemetry semantic-convention span attributes, so every
// exporter names a Redis command, a Kafka topic or a FastCGI request the same
// way.
package spanattributes

import (
	"go.opentelemetry.io/otel/attribute"

	"github.com/gma1k/podtrace/internal/events"
)

// Protocol returns the semantic-convention attributes for the protocol
// detail an event carries, or nil when its type has none beyond the target.
func Protocol(ev *events.Event) []attribute.KeyValue {
	if ev == nil {
		return nil
	}
	switch ev.Type {
	case events.EventRedisCmd:
		return database("redis", ev.Details)
	case events.EventMemcachedCmd:
		return database("memcached", ev.Details)
	case events.EventKafkaProduce:
		return messaging("send", "produce", ev.Details)
	case events.EventKafkaFetch:
		return messaging("receive", "poll", ev.Details)
	case events.EventFastCGIReq, events.EventFastCGIResp:
		return fastCGI(ev)
	default:
		return nil
	}
}

func database(system, operation string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{attribute.String("db.system.name", system)}
	if op := Token(operation); op != "" {
		attrs = append(attrs, attribute.String("db.operation.name", op))
	}
	return attrs
}

func messaging(operationType, operationName, destination string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("messaging.system", "kafka"),
		attribute.String("messaging.operation.type", operationType),
		attribute.String("messaging.operation.name", operationName),
	}
	if topic := Token(destination); topic != "" {
		attrs = append(attrs, attribute.String("messaging.destination.name", topic))
	}
	return attrs
}

func fastCGI(ev *events.Event) []attribute.KeyValue {
	attrs := []attribute.KeyValue{attribute.String("network.protocol.name", "fastcgi")}
	if method := Method(ev.Details); method != "" {
		attrs = append(attrs, attribute.String("http.request.method", method))
	}
	if path := Token(ev.Target); path != "" {
		attrs = append(attrs, attribute.String("url.path", path))
	}
	return attrs
}

// Token returns s up to its first space, control or non-ASCII byte. Probe
// strings are fixed-size buffers, so anything after that is not part of the
// value.
func Token(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c >= 0x7f {
			return s[:i]
		}
	}
	return s
}

// Method returns the leading run of ASCII letters in s.
func Method(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return s[:i]
		}
	}
	return s
}
