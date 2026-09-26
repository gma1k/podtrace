# Continuous inspections

The continuous metrics plane records what a workload is doing. Inspections are
the half that decides something is wrong.

Without them, an always-on APM still leaves the operator doing the work the
plane was supposed to remove: notice a line move on a dashboard, guess at a
cause, author a `PodTrace`, and hope the problem recurs while they are
watching. An inspection closes that loop, a rule that holds raises a typed
**issue**, and an issue can start a session on its own.

```
metrics  ──►  rule holds for `For`  ──►  issue activates
                                            │
                                            ├──►  podtrace_issue_active{...} = 1
                                            └──►  Kubernetes Event (source: issue)
                                                     │
                                                     └──►  PodTraceSchedule
                                                             trigger: Issue
                                                             └──►  PodTraceSession
                                                                     └──►  the trace
```

## Enabling it

Inspections live under the metrics plane, because they read that plane's own
series and would have nothing to evaluate without it:

They are on by default, with the metrics plane. On their own they page nobody:
an activated issue sets `podtrace_issue_active` and writes a Kubernetes Event
on the workload's pod. A session starts only when a `PodTraceSchedule` with an
`Issue` trigger exists, and a webhook fires only when
`agent.alerting` is configured. Both are yours to add.

To turn them off:

```bash
helm upgrade --install podtrace ghcr.io/gma1k/charts/podtrace \
  --set agent.metrics.inspections.enabled=false
```

To keep the rules evaluating but write no Events:

```bash
--set agent.metrics.inspections.enabled=true \
--set agent.metrics.inspections.alerts=false
```

That exposes `podtrace_issue_active` and writes no Events, so nothing starts a
session.

## Why rules read metrics, not events

The obvious implementation is to run the existing diagnostic detector over the
event stream. It would be wrong here, for two reasons:

1. **Under kernel-side aggregation there are no events.** The ring buffer
   carries nothing while the bypass is armed, so every rule would see an empty
   batch and report healthy, the worst failure mode an inspection can have,
   because it is indistinguishable from good news.
2. **An inspection has to agree with the dashboard beside it.** Reading the
   same gathered series a scrape returns makes a firing rule reproducible: the
   operator can run the rule's query themselves and get the same number.

So a rule evaluates over a snapshot of the agent's own registry. Whichever
path fed a metric, event stream or BPF map, the rule sees the identical
value.

## How long a condition must hold

A rule that is true for one interval is usually noise. Each rule therefore
carries a `For` duration: the condition must hold that long before the issue
activates, and the issue clears as soon as the condition stops holding. A
condition that flaps starts its `For` over rather than accumulating the time
the workload was healthy.

The durations differ per rule because the signals do. Saturation is real
within a minute; a latency regression needs longer to distinguish from a burst
of large requests.

## The rules

| Issue id | Fires when | `For` |
|---|---|---|
| `resource.saturation` | a container is near its CPU, memory or I/O limit | 1m |
| `l7.error_rate` | the workload's application-layer error ratio exceeds its threshold | 2m |
| `l7.latency_degraded` | the workload's mean request duration exceeds its threshold | 3m |
| `db.connection_acquire_slow` | callers spend a mean of 100ms or more obtaining a database connection | 2m |
| `db.pool_saturated` | a Go `database/sql` pool is at 80% or more of `SetMaxOpenConns` | 2m |
| `net.connection_failure_rate` | the workload's outbound connection attempts fail more often than its threshold; attempts with no route for their address family (a dual-stack client's IPv6-to-IPv4 fallback) are left out | 2m |
| `net.rtt_spike_rate` | more than 5% of the workload's socket operations run slower than 100ms; against a kernel-aggregated (native) histogram the bound is taken at the next bucket edge, 105ms, so it only counts observations certainly above 100ms | 3m |
| `cpu.contention` | the workload spends a mean of 500ms or more runnable but not running | 3m |

### The two planes now evaluate the same vocabulary

`net.connection_failure_rate` and `net.rtt_spike_rate` were part of the issue
vocabulary from the start but had no continuous rule, so the same id meant
something during a session and nothing the rest of the time. Both now fire
continuously, from `podtrace_workload_network_connections_total` and
`podtrace_workload_network_latency_seconds` respectively.

`net.connection_failure_rate` applies the same `minRequestsPerMinute` traffic
floor as `l7.error_rate`, which the session plane does not. That is the one
deliberate difference between the planes: a session inspects a bounded batch
an operator asked for, while this runs against every workload forever, where a
single failed connect in an idle interval reads as a 100% failure rate. Above
the floor the two agree, and a test pins that.

`net.rtt_spike_rate` keeps its name while measuring `tcp_sendmsg` and
`tcp_recvmsg` syscall duration rather than round-trip time, because the name is
carried in the `RTTSpikeMs` TracerConfig field, in alert routing and in the
`podtrace.threshold.rtt_spike.ms` OTel attribute. Its remediation says what is
actually being timed, so a slow peer no longer sends an operator to inspect the
network path. The name becomes literally true when the measurement moves to the
kernel's own `srtt_us`.

The rule reads the latency histogram's `le="0.1"` bucket rather than the mean,
because a handful of very slow operations and a uniformly mediocre workload
produce the same mean and need different answers. The bound must be one of the
histogram's bucket boundaries; the rule refuses to interpolate between them
rather than report a spike rate no observation supports.

Where `agent.sockOpsRTT` is on and the `sock_ops` hook attaches, the
rule reads `podtrace_workload_network_rtt_seconds` instead: the kernel's own
`srtt_us`, which makes the id's name literally true. Where it cannot attach —
kernel below 5.10, no cgroup v2, a runtime that declines
`BPF_CGROUP_SOCK_OPS` — the rule falls back to syscall latency rather than
going silent, because a working approximation beats a rule that never fires.
Every message names which of the two it measured, and the remediation differs
accordingly: the kernel reading sends you to the network path outright, the
fallback tells you to rule out a slow peer first.

### Saturation beyond the database

`db.pool_saturated` reads `podtrace_workload_db_pool_utilization_percent`,
which existed with no rule reading it. It fires *before*
`db.connection_acquire_slow`: a pool at 90% of its ceiling with fast acquires
has a problem that has not reached callers yet, which is the whole point of
sampling `numOpen` and `maxOpen` rather than waiting for queueing.

`cpu.contention` reads `podtrace_workload_cpu_runqueue_latency_seconds` and
carries `podtrace_workload_lock_contention_seconds` as evidence rather than as
a second rule.

It deliberately does **not** read `cpu_blocked_seconds`, which was the obvious
choice and the wrong one: that family counts every departure from the CPU, so
an idle pod sleeping in `epoll_wait` dominates it. Measured on an idle kind
node, an nginx serving nothing showed a 2825ms mean while a pod actually
serving traffic showed 102ms, so a rule reading it fired on precisely the
workloads that were healthy. The run-queue family counts only intervals that
began with a preemption, which is the workload wanting a CPU and not getting
one. An operator seeing this asks one
question first, whether the workload is waiting for a CPU or for a lock, and
the two need opposite fixes: more CPU, or fewer callers on a hot lock. When
lock waits are the longer of the two, the remediation says so.

`db.connection_acquire_slow` replaces the `pool.exhaustion` id that was
withdrawn before an earlier release. The withdrawal was right for the reason
given then, no metric measured the thing the name claimed, and the
replacement is named more narrowly on purpose. It reads
`podtrace_workload_db_connection_acquire_seconds`, which times
`database/sql.(*DB).conn` end to end and therefore cannot separate two causes:

- **queueing** for a free slot once the pool is at `SetMaxOpenConns`, which is
  exhaustion
- **establishing** a new connection while the pool is below its maximum,
  which is churn, usually from `SetMaxIdleConns` being too low

Both block the caller, so both deserve an issue; calling it exhaustion would
have been wrong in the second case. A workload churning connections fires this
rule while its own `sql.DBStats.WaitCount` reads zero, comparing the two is
how an operator tells which cause they have. The remediation text says so.

It keys on the mean rather than the count, because a thousand callers each
waiting a microsecond is a busy pool, not a slow one. Go `database/sql` only:
absence is not evidence of a healthy pool on a JVM, Node or Python workload.
See the saturation section of [continuous-metrics.md](continuous-metrics.md).

Each rule carries the PromQL an operator can run to see what it saw. For
example, `l7.error_rate` is:

```
100 * sum by (namespace, workload) (rate(podtrace_workload_l7_requests_total{outcome="error"}[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_l7_requests_total[5m]))
```

Note the `sum by`: the ratio is taken across the whole workload, not per
protocol. Dividing one protocol's errors by that protocol's own requests would
fire on a rarely-used protocol that failed once, true, and useless.

`resource.saturation` is the one rule both planes evaluate, and it bands
severity through the same function the diagnostic detector uses, so the same
reading cannot fire at two different severities depending on which plane saw
it.

### Thresholds

Rule *shapes* are not configurable, that is what keeps the issue vocabulary
meaningful. The numbers they compare against are:

```yaml
agent:
  metrics:
    inspections:
      enabled: true
      interval: 30s
      thresholds:
        errorRatePercent: 5
        minRequestsPerMinute: 6
        meanLatency: 1s
        acquireMean: 100ms
        cpuBlockedMean: 50ms
        poolUtilizationPercent: 80
```

`poolUtilizationPercent` is the warning band for `db.pool_saturated`; it
escalates to critical ten points higher.

`minRequestsPerMinute` is the traffic floor below which the error-rate rule
stays quiet. Without it, a single failed request during an idle interval reads
as a 100% error rate, which is arithmetically true and operationally
worthless, and would page someone for every idle workload in the cluster.

## Issue ids are contractual

An id appears in `podtrace_issue_active{id=...}`, in an alert's error code, and
in whatever alert routing you build on it. Under
[STABILITY.md](../STABILITY.md) that makes the vocabulary contractual: adding
an id is a minor, renaming one is breaking. A snapshot test fails when the
registry changes, so a rename cannot happen by accident.

## What is exposed

| Metric | What it tells you |
|---|---|
| `podtrace_issue_active{id,namespace,workload,pod,resource,severity}` | 1 while an issue is firing |
| `podtrace_inspections_evaluations_total` | the loop is running; a flat counter means it is not |
| `podtrace_inspections_failures_total` | passes that could not gather fully; rules are narrowed while this rises |
| `podtrace_inspections_transitions_total{id,transition}` | activations and recoveries |
| `podtrace_inspections_tracked_issues` | issue instances held against the budget |
| `podtrace_inspections_dropped_total` | instances refused because the budget was full |
| `podtrace_inspections_untriggerable_total` | activated issues that could not start a session |
| `podtrace_agent_issue_pod_unresolved_total` | issues for which no pod could be resolved |

A resolved issue's `podtrace_issue_active` series is **deleted**, not set to 0.
A series left at 0 keeps answering instant queries forever, so the issue list
would only ever grow and a dashboard filtered on the metric's presence would
list every issue the node had ever seen.

### Deliberately not a status condition

An issue is a metric, not a condition on a CR. Every agent in the fleet would
otherwise contend on the same object's status, a write per node per
evaluation, with the last writer winning and no way to tell whose reading you
are looking at. The same reasoning is recorded for kernel aggregation in
[continuous-metrics.md](continuous-metrics.md).

## Starting a session from an issue

An activated issue is raised as an alert with source `issue`, which the
existing flight-recorder contract already understands. To act on it:

```yaml
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSchedule
metadata:
  name: on-issue
  namespace: shop
spec:
  triggers:
    - source: Issue
      minSeverity: warning
  # ... session template
```

### The pod requirement

The trigger contract targets a **Pod** as the Event's involved object; the
operator ignores an Event that names anything else. Saturation issues already
name a pod, because the utilization gauge carries one. A workload-scoped issue,
an error rate, a latency regression — is about a Deployment, so the agent
resolves a representative pod of that workload from the pods it is already
tracking on its own node. Any replica is a valid target: the workload's
problem is present on every replica by definition of being the workload's.

When no pod can be resolved, the issue is still graphed and still logged, and
`podtrace_inspections_untriggerable_total` increments. That case is counted
rather than dropped in silence precisely because a silently open
metric-to-session loop looks exactly like a healthy one.

## Cost

An evaluation is one `Gather()` of the agent's own registry plus a linear pass
per rule. At the default 30s interval that is negligible beside the plane it
reads.

State is bounded: the engine tracks at most `budget` issue instances (512 by
default) and refuses new ones past that, counting the refusals. An unbounded
issue map inside an agent that must never be the reason a node degrades is not
an acceptable trade for completeness.

## Related documents

- [continuous-metrics.md](continuous-metrics.md), the surface inspections read
- [crd-podtraceschedule.md](crd-podtraceschedule.md), turning an issue into a session
- [alerting.md](alerting.md), where the alert goes
- [STABILITY.md](../STABILITY.md), what a version promises about issue ids
