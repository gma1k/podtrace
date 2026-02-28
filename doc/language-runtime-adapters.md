# Language-Runtime Adapters

Podtrace can trace application-level protocols and runtimes using library uprobes and socket kprobes — no changes to application code or container images required.

## Redis

Attaches to libhiredis (`redisCommand`, `redisCommandArgv`). Captures command name and latency.

```bash
# No configuration needed — libhiredis is detected automatically
./bin/podtrace -n production my-pod
```

Events emitted:

```
[REDIS] SET took 0.12ms
[REDIS] GET took 0.08ms
```

## Memcached

Attaches to libmemcached (`memcached_get`, `memcached_set`, `memcached_delete`). Captures operation, key, and value size.

```bash
# No configuration needed — libmemcached is detected automatically
./bin/podtrace -n production my-pod
```

Events emitted:

```
[CACHE] get session:abc123 took 0.15ms
[CACHE] set session:abc123 took 0.22ms (1024 bytes)
```

## FastCGI / PHP-FPM

Traces FastCGI request URI, HTTP method, and end-to-end latency via unix-socket kprobes. Requires a kernel with BTF support.

```bash
# No configuration needed — unix-socket traffic is inspected automatically (BTF-only)
./bin/podtrace -n production my-pod
```

Events emitted:

```
[FASTCGI] → POST /api/users
[FASTCGI] ← /api/users 42.10ms (status=0)
```

> **Note:** FastCGI tracing requires a kernel built with BTF (BPF Type Format) support. On kernels without BTF, the FastCGI hooks are no-ops.

## gRPC

Extracts the gRPC method path from HTTP/2 HEADERS frames. Uses a second kprobe on `tcp_sendmsg`, filtered by destination port (default 50051). Requires BTF.

```bash
# Use the default gRPC port (50051)
./bin/podtrace -n production my-pod

# Override gRPC port if not using the default
export PODTRACE_GRPC_PORT=9090
./bin/podtrace -n production my-pod
```

Events emitted:

```
[gRPC] /helloworld.Greeter/SayHello took 1.23ms
```

> **Note:** gRPC tracing requires BTF support. The port filter defaults to 50051 and can be changed with `PODTRACE_GRPC_PORT`.

## Kafka

Attaches to librdkafka (`rd_kafka_produce`, `rd_kafka_consumer_poll`). Captures topic name, payload size, and latency for both produce and consume paths.

```bash
# No configuration needed — librdkafka is detected automatically
./bin/podtrace -n production my-pod
```

Events emitted:

```
[KAFKA] produce orders 0.45ms (512 bytes)
[KAFKA] fetch orders 5.10ms (2048 bytes)
```

## Critical Path Reconstruction

Enabled by default. Correlates latency segments by PID within a sliding time window and logs a breakdown whenever an HTTP response, FastCGI response, or gRPC call completes.

```bash
export PODTRACE_CRITICAL_PATH=true              # default
export PODTRACE_CRITICAL_PATH_WINDOW_MS=500     # default (ms)
./bin/podtrace -n production my-pod
```

Example output:

```
[CRITICAL PATH] PID 1234 total=45.2ms
  DNS lookup        12.1ms  26.8%
  TCP connect        2.3ms   5.1%
  TLS handshake      8.4ms  18.6%
  File read          4.7ms  10.4%
  HTTP response     17.7ms  39.2%
```

Segments are collected from all events with non-zero latency for a given PID. The window is finalized on the first HTTP response, FastCGI response, or gRPC method event received for that PID. Windows older than `PODTRACE_CRITICAL_PATH_WINDOW_MS` milliseconds are automatically evicted.

## PII Redaction

Applies regex rules to `Target` and `Details` fields before events reach any consumer. Built-in rules cover passwords, Bearer tokens, email addresses, and credit card numbers.

```bash
export PODTRACE_REDACT_PII=true
./bin/podtrace -n production my-pod
```

Built-in redaction rules:

| Pattern | Replacement |
|---|---|
| `password=<value>` | `password=***` |
| `Bearer <token>` | `Bearer ***` |
| Email addresses | `***@***` |
| 16-digit card numbers | `****-****-****-****` |

### Custom Redaction Rules

Set `PODTRACE_REDACT_CUSTOM_RULES` to a JSON array of additional rules (applied after built-in rules). Each rule requires a `name`, `pattern` (Go regex), and `replace` string.

## USDT Auto-Detection

Scans the container binary's ELF `.note.stapsdt` section to discover available userspace tracepoints (USDTs).

```bash
export PODTRACE_USDT_ENABLED=true
./bin/podtrace -n production my-pod
```

When enabled, Podtrace logs all discovered USDT probes at startup:

```
[USDT] found probe ruby::method-entry at 0x4a1f20
[USDT] found probe python::function__entry at 0x3b8c10
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PODTRACE_GRPC_PORT` | `50051` | Destination port used to identify gRPC traffic |
| `PODTRACE_USDT_ENABLED` | `false` | Enable USDT probe scanning on the container binary |
| `PODTRACE_REDACT_PII` | `false` | Scrub PII from event Target/Details fields |
| `PODTRACE_REDACT_CUSTOM_RULES` | `""` | JSON array of additional redaction rules |
| `PODTRACE_CRITICAL_PATH` | `true` | Emit per-request latency breakdowns |
| `PODTRACE_CRITICAL_PATH_WINDOW_MS` | `500` | Window (ms) before an open PID window is evicted |
