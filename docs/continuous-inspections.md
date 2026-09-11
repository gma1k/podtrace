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

```bash
helm upgrade --install podtrace ghcr.io/gma1k/charts/podtrace \
  --set agent.metrics.enabled=true \
  --set agent.metrics.inspections.enabled=true
```

They are off by default for one reason: this is the half that can page
someone. Turning the metrics plane on is a cost decision; turning inspections
on is an operational one.

To watch what the rules *would* have fired on before letting them alert:

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
```

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
