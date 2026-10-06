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

## Critical path

A `--diagnose` run, and so every session report, breaks the duration of each
request the target served down by where it went: waiting on the network, a
database, a cache, DNS, a TLS handshake, a connect, the filesystem or a lock.
On by default; `PODTRACE_CRITICAL_PATH=false` turns it off. The agent never
does this.

```text
Request Time Breakdown:
  Requests served: 576 (HTTP/1 576)
  Where their time went: network 98.4%, not in traced I/O 1.5%, dns 0.1%
  By endpoint, most total time first:
    GET /slow  288 requests, mean 302.2ms
              network 98.5%, not in traced I/O 1.4%, dns 0.1%
    GET /fast  288 requests, mean 200µs
              not in traced I/O 100.0%
  Slowest requests:
    303.1ms   GET /slow  cp-demo/api-bc8564b55-2l42g  (HTTP/1)
              network 99.2%, not in traced I/O 0.7%, dns 0.1%
    ...
  Each stretch of a request is counted once, under its most specific wait, so the shares add up to the request.
```

That is a Python `ThreadingHTTPServer` on kind whose `/slow` handler calls a
backend that answers in 300ms: the call is the network share, the lookup of
the backend's name the dns share.

**How a wait is joined to its request.** The kernel stamps every event with
the correlation id of the request its thread, goroutine or connection is
serving, chosen the same way the [on-CPU profiler](profiling.md) charges a
sample, and reports when a served request finishes. Two requests in flight in
one process are therefore kept apart: each is charged only its own waits.

**How the shares are counted.** Each wait is an interval. Where intervals
overlap, the time goes to the most specific one, so a database query's socket
read counts once, as database, and two calls made in parallel count once.
What no traced wait covers is reported as *not in traced I/O*: running on a
CPU, waiting to be scheduled, or waiting on something podtrace does not trace.
The shares of a request always add up to its duration.

**What it can and cannot see.**

- **Blocking I/O is visible; a non-blocking runtime's network wait is not.**
  A thread-per-request server that blocks in `read` (Java servlets on
  blocking sockets, Python and Ruby workers, PHP-FPM, most C++ servers) shows
  its backend waits as network time. Go, Node.js, nginx, Envoy, Netty and
  tokio read non-blocking sockets and wait in `epoll`: the read itself
  returns at once, so their network waits land in *not in traced I/O*. Their
  filesystem, lock and connect waits, and database or cache calls made
  through a traced client library, are still joined.
- **Go request ids need kernel 5.15.** Finding the goroutine from inside a
  kernel probe needs `bpf_task_pt_regs`; on 5.8 to 5.14 a Go request's waits
  are left unjoined rather than guessed.
- **Only HTTP/1 requests are named.** A Go request's id comes from its
  handler, which podtrace does not read the URL from, and HTTP/2 and HTTP/3
  requests are decoded with ids of their own; their requests are listed as
  *(endpoint not seen)*, with their kind.
- **An outbound HTTP call is not a category of its own.** The call carries
  its own correlation id, so its time shows as the socket waits under it.
- **Filesystem operations under 1ms are counted but are not events**, so a
  request does not see them as waits and they are part of *not in traced
  I/O*. Neither are reads and writes on pipes and sockets, which the
  network family covers.
- **`--filter` narrows the breakdown too.** The waits a filter drops never
  reach it, so with `--filter dns` a request's socket waits count as *not in
  traced I/O*; the section says which categories were kept.

The collector keeps at most 8192 unfinished requests and 512 waits per
request; the report says how many requests or waits it could not count.

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

Set `PODTRACE_REDACT_CUSTOM_RULES` to a JSON array of additional rules (applied after built-in rules). Each rule requires a `name`, `pattern` (Go regex), and `replace` string. A rule with an invalid pattern is skipped with a logged error — the built-in rules and any valid custom rules still apply, so redaction never silently degrades to a no-op.

### Enabling redaction in Kubernetes

The env vars above configure a standalone tracer. In a cluster, set redaction once on the `TracerConfig` and it applies to **both** the agent DaemonSet and every session Job — no per-pod env editing, and it survives operator reconciliation:

```yaml
apiVersion: podtrace.io/v1alpha1
kind: TracerConfig
metadata:
  name: default
spec:
  image: ghcr.io/gma1k/podtrace:latest
  redaction:
    enabled: true
    redactDNSNames: false        # also scrub DNS query names
    customRules:
      - name: ssn
        pattern: '\d{3}-\d{2}-\d{4}'
        replace: '***-**-****'
```

Via Helm, the same is exposed under `tracerConfig.redaction` in `values.yaml`. The operator translates these fields into the `PODTRACE_REDACT_*` env vars on the tracer containers.

## USDT Auto-Detection

Scans the container binary's ELF `.note.stapsdt` section to discover available userspace tracepoints (USDTs).

USDT scanning is enabled by default. Disable it by setting the environment
variable to `false` (or `agent.usdt: false` in the Helm chart):

```bash
export PODTRACE_USDT_ENABLED=false
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
| `PODTRACE_USDT_ENABLED` | `true` | Scan the container binary for USDT probes; set `false` to disable |
| `PODTRACE_REDACT_PII` | `false` | Scrub PII from event Target/Details fields |
| `PODTRACE_REDACT_CUSTOM_RULES` | `""` | JSON array of additional redaction rules |
| `PODTRACE_CRITICAL_PATH` | `true` | Break served requests down by where their time went in `--diagnose` runs |
