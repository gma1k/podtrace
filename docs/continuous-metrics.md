# Continuous metrics

Podtrace exposes two Prometheus surfaces. This page documents the
**continuous** one: workload metrics aggregated by the always-on agent and
intended for a permanent scrape.

The other surface is the **diagnostic** one in [metrics.md](metrics.md), served
by the CLI behind `--metrics` for the duration of one tracing run. The two are
separate on purpose and neither replaces the other:

| | Diagnostic | Continuous |
|---|---|---|
| Served by | the CLI, per run | the agent, always |
| Lifetime | one invocation | as long as the node |
| Scoped to | the pods that run targets | every pod on the node |
| Labelled by | process and pod | namespace, workload, container |
| Latency shape | histograms and latest-value gauges | histograms only |
| Answers | *why* is this pod slow | *which* workload is unhealthy |

## Enabling it

Off by default. One Helm value turns it on:

```bash
helm upgrade --install podtrace deploy/charts/podtrace \
  --set agent.metrics.enabled=true \
  --set metrics.podMonitor.enabled=true
```

The first flag enables the plane; the second tells Prometheus to scrape it.
Series appear on the endpoint the agent already serves, so the `PodMonitor`
shipped with the chart needs no further configuration.

Once enabled the agent observes **every pod on the node**, not only those a
`PodTrace` or `ApplicationTrace` targets. Coverage does not require
authoring an object, that is the difference between this plane and
on-demand diagnostics.

### Chart values

```yaml
agent:
  metrics:
    enabled: false
    excludeNamespaces: []      # skipped by the plane; diagnostics unaffected
    seriesBudget: 0            # 0 uses the built-in default of 40000
    nativeHistograms: true
    labels:
      pod: false               # each of these multiplies series count
      process: false
```

These map onto `TracerConfig.spec.agent.metrics`. Editing the CR directly
works but gets reverted on the next chart upgrade, so prefer
`helm upgrade --reuse-values --set …`, same rule as every other
TracerConfig field, see [crd-tracerconfig.md](crd-tracerconfig.md).

### Cost, measured

Enabling the plane costs real CPU, because it attaches probes to *every*
pod on the node: every pod's events cross the ring buffer into userspace and
the plane aggregates each one. Cost scales with **event volume**, not with
series count.

Measured on a 3-node kind cluster running Cilium, cert-manager and CoreDNS,
on the node with the workload:

| Configuration | Observations/sec | Agent CPU |
|---|---|---|
| Plane off | — | 0.01 cores |
| Plane on, default categories | ~34,000 | ~0.12 cores |
| Plane on, `fs` included | ~67,000 | up to 1.00 cores |

The third row is why the plane does not enable the `fs` category. Filesystem
events alone were **94.9%** of all observations — 63,000 per second on one
agent against 3,100 for network bytes — and including them drove the agent
to the chart's default 1-core limit. Filesystem latency is a diagnostic
signal rather than a golden one, so the plane does not pay for it; the two
filesystem families still populate whenever a `PodTrace` asks for `fs`.

With the default categories the remaining volume is dominated by network
byte counting. That is the next thing to get cheaper.

Practical guidance:

- Watch the agent's own CPU after enabling it (see below). If it approaches
  `agent.resources.limits.cpu`, raise the limit or narrow coverage — a
  throttled agent drops events and the metrics under-report.
- Use `excludeNamespaces`. System namespaces usually produce a large share
  of the events and the least interesting metrics.
- Moving aggregation into the kernel, so a metrics-only node produces no
  per-event userspace traffic at all, is the planned structural fix.


### Watch for throttling, not just for drops

The failure mode to alert on is **silent under-reporting**. If the agent is
throttled at its CPU limit it stops keeping up with the kernel, events are
lost before the plane ever sees them, and the dashboards keep looking
healthy while the numbers are wrong. Nothing in the workload metrics
themselves reveals this — a lower rate is indistinguishable from less
traffic.

Three signals together tell you whether to trust the surface:

```promql
# Is the agent at its CPU limit? (the agent's own process metrics)
rate(process_cpu_seconds_total{job="podtrace-agent"}[5m])

# Is the kernel losing events before userspace sees them?
sum by (reason) (rate(podtrace_agent_kernel_events_dropped_total[5m]))

# How much is the plane actually absorbing?
sum by (outcome) (rate(podtrace_workload_metrics_events_total[5m]))
```

The agent exposes Go and process collectors on the same endpoint, so the
first query needs no extra exporter. If CPU is pinned at the limit while
kernel drops are non-zero, the workload metrics are undercounting and
raising the CPU limit or narrowing coverage comes before trusting any
number on the dashboard.

### Environment variables

The operator renders the CR fields into agent environment. These are the
underlying knobs, useful when running the agent outside the operator:

| Variable | Default | Field |
|---|---|---|
| `PODTRACE_WORKLOAD_METRICS` | `false` | `enabled` |
| `PODTRACE_WORKLOAD_METRICS_EXCLUDE_NAMESPACES` | empty | `excludeNamespaces`, comma-separated |
| `PODTRACE_WORKLOAD_METRICS_SERIES_BUDGET` | `40000` | `seriesBudget` |
| `PODTRACE_WORKLOAD_METRICS_NATIVE_HISTOGRAMS` | `true` | `nativeHistograms` |
| `PODTRACE_WORKLOAD_METRICS_POD_LABEL` | `false` | `labels.pod` |
| `PODTRACE_WORKLOAD_METRICS_PROCESS_LABEL` | `false` | `labels.process` |

Two more knobs have no CRD field, because they tune eviction rather than
what is measured:

| Variable | Default | Meaning |
|---|---|---|
| `PODTRACE_WORKLOAD_METRICS_SERIES_TTL` | `15m` | How long a series may go unobserved before it is deleted |
| `PODTRACE_WORKLOAD_METRICS_REAP_INTERVAL` | `1m` | How often the agent checks for idle series |

Nothing is rendered when the plane is disabled, so a cluster not using it
sees a byte-identical agent pod template and no rollout.

## Labels

Every workload family carries the same four base labels:

| Label | Source | Why this one |
|---|---|---|
| `namespace` | pod namespace | |
| `workload` | controller owner name, with `ReplicaSet` resolved to its `Deployment` | Survives a rollout; a pod name does not |
| `workload_kind` | `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `Pod`, … | Functionally determined by `workload`, so it costs no extra series |
| `container` | container name | |

Notably **absent**, and deliberately so:

- **`pod`**: a pod name changes on every rollout, so a pod label mints a
  fresh series each deploy and retires the old one. That churn, not the
  instantaneous series count, is the dominant cost in Prometheus.
- **`process_name`**: unbounded, and bounding it to the top *N* leaves an
  `other` bucket that answers nothing.

Both are available on the diagnostic surface, where the run is short enough
for them to be free, and both belong on spans rather than series when you
need per-request detail.

If you need one of them here anyway, `agent.metrics.labels.pod` and
`agent.metrics.labels.process` add them. Expect the series count to rise by
roughly the number of pods per workload, or the number of distinct process
names, and size `seriesBudget` accordingly.

## Workload metrics

These are the contractual surface. Metric names and label keys follow the
rule in the [*Metrics surface*](../STABILITY.md#metrics-surface) section of
STABILITY.md: a minor release may rename or relabel them, a patch release may
not.

### Application layer

| Metric | Type | Extra labels |
|---|---|---|
| `podtrace_workload_l7_requests_total` | Counter | `protocol`, `status_class`, `outcome` |
| `podtrace_workload_l7_request_duration_seconds` | Histogram | `protocol` |

`protocol` is one of `http`, `http2`, `http3`, `grpc`, `fastcgi`, `redis`,
`memcached`, `kafka`, `database`, `unknown`. HTTP/2 and HTTP/3 keep their own
values rather than collapsing into `http`, because distinguishing them is the
point of podtrace's L7 coverage.

`status_class` is `1xx` through `5xx`, or `unknown` when the probe could not
recover a status. The class rather than the exact code is deliberate: a code
multiplies every L7 series by the number of codes a real service returns, and
buys nothing a class does not. The exact code belongs on a span, where it
costs one attribute instead of one series.

`outcome` is `ok` or `error`, so an error ratio is one query rather than a sum
over classes. A `4xx` is a client error and counts as `ok` — it is a failure
of the request, not of the workload being observed, and remains visible
through `status_class`.

### OpenTelemetry semantic conventions

Enabled with `agent.metrics.semanticConventions=true`, the plane also emits
the convention's own names for the L7 signals, **in addition to** the native
families above. That doubling is the point: a stock Grafana, Datadog or
Honeycomb dashboard queries these names, so podtrace becomes a drop-in
inside a stack you already run rather than a second dialect to learn.

| Metric | Attributes |
|---|---|
| `http_server_request_duration_seconds` | `http_request_method`, `http_response_status_code`, `network_protocol_name` |
| `rpc_server_duration_seconds` | `rpc_system`, `rpc_method` |
| `db_client_operation_duration_seconds` | `db_system_name`, `db_operation_name` |

These carry **no `podtrace_` prefix** — the names belong to the convention,
and prefixing them would make them invisible to the dashboards they exist to
serve.

Identity arrives as `service_name`, `k8s_namespace_name` and
`k8s_container_name`. `service_name` is the workload, because that is the
label conventional dashboards group by. Semconv's workload keys are
kind-specific (`k8s.deployment.name`, `k8s.statefulset.name`, …) and a
Prometheus family has one fixed label set, so there is no single key that
could carry the workload for every kind.

Three deliberate differences from the native families:

- **`http_response_status_code` is the real code**, not the class. The
  convention expects a code, and a dashboard filtering `status >= 500`
  cannot work on `"5xx"`. This costs roughly ten times the cardinality on
  that one family.
- **`rpc_method` and `db_operation_name` are bounded.** Both come from
  observed traffic, so their value space is open; past
  `PODTRACE_WORKLOAD_METRICS_ATTRIBUTE_CARDINALITY` (default 50) the tail
  folds into `_other` rather than minting series without end.
- **Kafka and FastCGI are absent.** Neither has a server-duration
  convention, and forcing them into one would misdescribe them. They remain
  on the native `podtrace_workload_l7_*` families.

`http.route` is not emitted. podtrace observes the wire, so it sees the
request target rather than the server's route template, and the convention
explicitly warns against substituting the raw path.

#### When the method is `_OTHER`

`http_request_method` carries the real method on every transport podtrace
decodes: HTTP/1.x reads it off the request line in BPF, and HTTP/2 and
HTTP/3 read the `:method` pseudo-header out of HPACK and QPACK
respectively. The method travels request-to-response, because the duration
is only known once the response arrives.

It falls back to `_OTHER` — the convention's own placeholder — in two
cases, both of them honest:

- **The method was outside the convention's set.** `:method` is an
  arbitrary token chosen by the peer, so it is folded to
  GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS/CONNECT/TRACE and anything else
  becomes `_OTHER`. Passing the raw token through would hand Prometheus an
  unbounded, peer-chosen label dimension, which is precisely what the
  series budget cannot defend against.
- **No method was recovered at all.** On a late-joined HTTP/2 connection
  the `:method` may have been indexed into the dynamic table before
  capture attached, and some C-library HTTP/3 adapters measure timing
  without decoding the peer's headers.

`http_response_status_code` is `0` on the same principle, for a response
whose status could not be recovered — a gRPC-over-h2 stream, most often.
The convention would have the attribute omitted; a Prometheus family has
one fixed label set and cannot omit a label, so `0` is the sentinel.

### Network, DNS, filesystem, CPU, TLS

| Metric | Type | Extra labels |
|---|---|---|
| `podtrace_workload_network_latency_seconds` | Histogram | `direction`, `transport` |
| `podtrace_workload_network_bytes_total` | Counter | `direction`, `transport` |
| `podtrace_workload_dns_latency_seconds` | Histogram | — |
| `podtrace_workload_filesystem_latency_seconds` | Histogram | `operation` |
| `podtrace_workload_filesystem_bytes_total` | Counter | `operation` |
| `podtrace_workload_cpu_blocked_seconds` | Histogram | — |
| `podtrace_workload_tls_handshake_duration_seconds` | Histogram | — |
| `podtrace_workload_errors_total` | Counter | `kind` |

`direction` is `ingress` or `egress`; `transport` is `tcp` or `udp`.
`operation` is `read`, `write`, `fsync`, `open`, `close`, `unlink` or
`rename`. `kind` groups failures as `l7`, `dns`, `network`, `filesystem`,
`tls` or `other`.

## Plane internals

These describe the metrics plane's own behaviour rather than the workload, so
they **carry no compatibility promise**, same tier as the collector
internals in [metrics.md](metrics.md).

| Metric | Description |
|---|---|
| `podtrace_workload_metrics_events_total` | Events reaching the plane, labeled `outcome`: `aggregated`, `unattributed`, or `ignored` |
| `podtrace_workload_metrics_series_dropped_total` | Observations refused because a new series would exceed the budget, labeled `family` |
| `podtrace_workload_metrics_series_active` | Distinct label combinations currently held, counted against the budget |
| `podtrace_workload_metrics_series_reaped_total` | Series removed after their workload stopped being observed, freeing budget |

`unattributed` is worth an alert. It counts events that arrived with no pod
metadata, which means the identity join failed and those observations were
discarded rather than filed under a wrong or placeholder workload. A steadily
rising `unattributed` means the plane is running but measuring nothing.

## Pushing the plane over OTLP

The plane is a scrape target by default. It can also be pushed, as a second
signal on an `ExporterConfig` that already carries spans:

```yaml
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata:
  name: collector
spec:
  type: otlp
  otlp:
    endpoint: otel-collector.observability:4318
    metrics:
      enabled: true
      interval: 60s
```

Same object, same endpoint, same headers: metrics authenticate exactly as
the spans do. That reaches every OTLP-compatible backend without a
per-vendor metrics SDK, and it is deliberately **not** Prometheus
remote-write — a Collector does remote-write better, and forwarding rather
than storing keeps podtrace out of the storage business.

Two conditions have to hold for anything to be sent. The plane must be on
(`TracerConfig.spec.agent.metrics.enabled`), because the push republishes
the surface rather than producing a second one; and a PodTrace must
reference the `ExporterConfig`, because that is what tells the agent to
build the exporter at all.

`interval` defaults to 60s, matching a conventional scrape period, and is
clamped to 10s–10m: below the floor the cost outruns what a cumulative
counter can reveal, and above the ceiling a dashboard reads the gap as an
outage.

### What the push looks like on the wire

The Prometheus registry stays the single source of truth. The push reads
the surface that already exists rather than recording a second copy of it,
so the series budget, the cardinality bound and the reaper apply to both
paths identically and cannot drift apart.

Names differ between the two paths, in one direction only:

| Surface | Scrape | OTLP |
|---|---|---|
| Convention families | `http_server_request_duration_seconds` | `http.server.request.duration` |
| Convention attributes | `http_request_method` | `http.request.method` |
| podtrace's own families | `podtrace_workload_l7_requests_total` | unchanged |

The convention families get their dotted names back because that is what an
OTLP-native backend recognises, and dropping to the Prometheus rendering
there would undo the point of emitting them. podtrace's own names have no
convention to honour, so they travel verbatim — the same thing a
Collector's `prometheus` receiver does with a scrape. Rename them in the
Collector if you want something else.

Workload identity arrives as data-point attributes, not as the OTLP
Resource. A Resource belongs to the exporting provider and one provider
serves every workload on the node, so `service.name` on the Resource is
`podtrace` (with `k8s.node.name` beside it) while the observed workload
travels as the `service.name` **attribute**. That is again what the
Collector's Prometheus receiver produces, so both paths agree.

All instruments are cumulative, because the underlying Prometheus counters
are. Native histograms cross as OTLP exponential histograms; classic
buckets cross as explicit-bucket histograms.

### One stream per collector, not per CR

Spans are per-CR: a span belongs to the trace some CR asked for. A counter
does not. So several PodTraces pointing at one collector share a single
metric stream — pushing one per CR would send the same node-wide counters
two or three times and make every sum across them wrong. Two CRs pointing
at *different* collectors get one stream each, which is fan-out and
correct.

A metrics receiver that cannot be reached does not take tracing down with
it: spans keep flowing and the failure is reported through the exporter's
own init-failure metric.

## Histograms

Latency families are exposed as native histograms *and* classic buckets, so
scrapers without native-histogram support still get usable quantiles. Set
`PODTRACE_WORKLOAD_METRICS_NATIVE_HISTOGRAMS=false` to emit classic buckets
only.

The classic layout is twelve buckets spanning 500µs to 30s. The count is
deliberate: the diagnostic surface uses `ExponentialBuckets(0.0001, 2, 20)`,
which is 22 series per label combination, and at this surface's family count
that layout alone would exceed the per-node budget. Query quantiles with
`histogram_quantile` rather than depending on specific `le` values — bucket
boundaries are explicitly outside the compatibility promise.

## The series budget

The budget is a hard cap on distinct label combinations per node, enforced at
a single chokepoint that every observation passes through. When it is
reached, new series are refused and counted in
`podtrace_workload_metrics_series_dropped_total`; series already admitted keep
recording. A documented cap that is not enforced is not a cap.

The `40000` default is derived rather than guessed. Roughly 20 workloads ×
1.5 containers × 3 per-family variants is about 90 label combinations per
family, which across this surface's families lands near 7,000 series per node
with native histograms. The headroom above that covers the second name per
metric that OpenTelemetry-convention naming will add.

Sizing it for your own cluster:

```promql
# Series this plane holds, per node
podtrace_workload_metrics_series_active

# Whether anything is being refused
sum by (family) (rate(podtrace_workload_metrics_series_dropped_total[5m]))
```

### Series are evicted when their workload goes away

A series whose workload stops being observed is deleted after
`PODTRACE_WORKLOAD_METRICS_SERIES_TTL` (default 15 minutes), and
`podtrace_workload_metrics_series_reaped_total` counts the removals.

This is not a tidiness feature. Without it the plane leaks: a deleted
Deployment's series stay registered forever, so a cluster with ordinary
rollout churn accumulates dead series until the budget fills — and then
refuses new series for *live* workloads while still holding the dead ones.
The budget would end up spent on history.

Deleting rather than merely stopping updates also matters to the consumer:
a series that goes quiet keeps answering instant queries with its last
value until Prometheus staleness handling takes over.

If drops are non-zero, either raise the budget or narrow what the plane
observes — do not ignore it, because which series get refused depends on
arrival order and is therefore arbitrary.

The agent also logs once, at error level, on the transition into
exhaustion. There is deliberately **no** `TracerConfig` status condition for
this: `status.conditions` is keyed by type alone, so every agent on every
node would contend for the same entry and flap it as their individual
budgets filled at different times. A per-node status array would be needed
to express it correctly, and a rate-shaped signal like this is better served
by the counter above.

## Example queries

```promql
# Request rate per workload
sum by (namespace, workload) (
    rate(podtrace_workload_l7_requests_total[5m])
)

# Error ratio per workload
sum by (namespace, workload) (
    rate(podtrace_workload_l7_requests_total{outcome="error"}[5m])
) / sum by (namespace, workload) (
    rate(podtrace_workload_l7_requests_total[5m])
)

# p99 request duration, by protocol
histogram_quantile(0.99,
    sum by (namespace, workload, protocol, le) (
        rate(podtrace_workload_l7_request_duration_seconds_bucket[5m])
    )
)

# p99 for HTTP/3 traffic only — the query no other eBPF tool can answer
histogram_quantile(0.99,
    sum by (namespace, workload, le) (
        rate(podtrace_workload_l7_request_duration_seconds_bucket{protocol="http3"}[5m])
    )
)

# Egress throughput per workload
sum by (namespace, workload) (
    rate(podtrace_workload_network_bytes_total{direction="egress"}[5m])
)
```

## Related documents

- [metrics.md](metrics.md), the diagnostic surface and its naming rules
- [STABILITY.md](../STABILITY.md), what a version promises about metric names
- [crd-tracerconfig.md](crd-tracerconfig.md), agent fleet configuration
