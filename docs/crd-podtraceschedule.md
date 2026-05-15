# PodTraceSchedule — recurring diagnose CR

`PodTraceSchedule` is the cron analogue of [`PodTraceSession`](crd-podtracesession.md):
it runs a fresh `PodTraceSession` on a recurring schedule. Use it for
nightly diagnose sweeps, hourly probes against a flaky deployment, or
on-call SRE workflows where someone should always have the last minute
of eBPF events ready to look at.

A schedule does not run any eBPF itself. The controller materialises one
`PodTraceSession` per scheduled run; the session then runs the same per-node Job
diagnose path as if it had been created by hand.

## Minimal example

```yaml
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata:
  name: prod-otlp
  namespace: my-app
spec:
  type: otlp
  otlp:
    endpoint: otel-collector.observability:4318
    protocol: http
    insecure: true
---
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSchedule
metadata:
  name: nightly-diagnose
  namespace: my-app
spec:
  schedule: "0 2 * * *"          # every day at 02:00 (operator local TZ)
  concurrencyPolicy: Forbid       # do not overlap if a run is still in flight
  successfulSessionsHistoryLimit: 7
  failedSessionsHistoryLimit: 3
  sessionTemplate:
    spec:
      selector:
        matchLabels:
          app: api
      duration: 5m
      filters: [dns, net, fs]
      exporterRef:
        name: prod-otlp
```

## Spec reference

| Field | Type | Required | Notes |
|---|---|---|---|
| `schedule` | string | yes | Cron expression. Accepts the standard 5-field form (`*/5 * * * *`), the 6-field form with leading seconds (`0 */5 * * * *`), and descriptors (`@hourly`, `@daily`, `@every 5m`). Validated at admission. |
| `timeZone` | string | no | IANA name (`Europe/Amsterdam`). Defaults to the operator's local timezone. |
| `concurrencyPolicy` | enum | no | `Allow` (default), `Forbid`, or `Replace`. See below. |
| `startingDeadlineSeconds` | int | no | If the controller is late by more than this many seconds, the missed run is skipped. Unset = no deadline. |
| `successfulSessionsHistoryLimit` | int | no | Max completed children kept. Default 3. |
| `failedSessionsHistoryLimit` | int | no | Max failed children kept. Default 1. |
| `suspend` | bool | no | When true the controller refreshes status but does not run. |
| `maxActiveSessions` | int | no | Safety valve. When in-flight children (state empty/Pending/Running) reach this many, runs are skipped until something drains. Unset or `0` = no cap. See "Production tip" below. |
| `sessionTemplate.metadata` | partial ObjectMeta | no | `labels` and `annotations` are propagated to each child session. |
| `sessionTemplate.spec` | `PodTraceSessionSpec` | yes | Same shape as a standalone session — promote an existing manifest by wrapping its `spec:` under `spec.sessionTemplate.spec:`. |

### ConcurrencyPolicy

| Value | Behaviour |
|---|---|
| `Allow` (default) | Run on every tick; previous sessions are not consulted. Use for short, non-overlapping diagnose windows. |
| `Forbid` | If any session launched by the schedule is still active, skip the tick. Use when overlapping sessions would multiply load on the target pods. |
| `Replace` | Delete any active session and start a new one. Use for "always sample the latest window" workflows. |

> **Production tip.** Prefer `Forbid` for any schedule whose template is
> non-trivial. The session→Job fanout has a finite throughput, and a
> bursty cluster (kind, autoscaler scale-from-zero, node pressure) can
> let `Allow` schedules accumulate sessions in `state=""` while their
> Jobs queue. `Forbid` self-throttles in this case; `Replace` keeps
> exactly one run in flight; `Allow` is best reserved for short
> diagnose windows you know will complete inside the schedule interval.
> If you must use `Allow`, set `spec.maxActiveSessions` as a safety
> valve — when the cap is hit the next run is skipped and the
> Reconciled condition records `ActiveLimitReached`.

## Status

| Field | Notes |
|---|---|
| `active` | List of currently-active child sessions. |
| `lastScheduleTime` | The scheduled-run time the controller most recently acted on. |
| `lastSuccessfulTime` | Completion time of the most recent successful child. |
| `conditions` | `Reconciled`, `Degraded`, `Paused`. |

`Degraded=True` carries reasons like `ScheduleInvalid` (cron expression
fails to parse — should be caught by the webhook in normal flows) and
`CreateSession` (apiserver rejected the materialised child).
`Paused=True` indicates `spec.suspend=true`.

## Manual triggers

The bundled `kubectl` plugin can trigger a one-off session from a
schedule's template:

```bash
# Honour the schedule's concurrencyPolicy and suspend gate.
kubectl podtrace schedule trigger nightly-diagnose -n my-app

# Bypass policy and Suspend — emergency diagnose only.
kubectl podtrace schedule trigger nightly-diagnose -n my-app --force

# Print the rendered session without applying it.
kubectl podtrace schedule trigger nightly-diagnose -n my-app --print-only
```

Without `--force`, the session created carries an owner reference back
to the schedule, so it shows up in `status.active` and counts against
`successfulSessionsHistoryLimit`. With `--force`, the session has no
owner reference and is not affected by the schedule's policy.

## Lifecycle and garbage collection

Each child session is owned by the schedule via Kubernetes owner
references. Deleting the schedule cascades through built-in garbage
collection — there is no finalizer to wait on.

History limits prune older children oldest-first by
`status.completionTime` (fallback `metadata.creationTimestamp`).
Children created without an owner reference (e.g. via
`trigger --force`) are never garbage-collected by the schedule.

## Reading the events each run captured

A schedule fires `PodTraceSession`s — to actually inspect what each
run captured, set `sessionTemplate.spec.reportRef` and read the
output:

```yaml
sessionTemplate:
  spec:
    # ...
    reportRef:
      configMap: { name: nightly-report }     # overwritten each run, "latest snapshot"
    # or, for per-run archiving:
    # objectStore:
    #   uri: "s3://my-bucket/podtrace/"
    #   credentialsSecretRef: { name: s3-creds }
```

Then `kubectl get cm nightly-report -o jsonpath='{.data.report\.txt}'`
for the latest run, or `aws s3 ls s3://my-bucket/podtrace/` for the
archived history.

For all four surfaces (live CLI, ConfigMap, ObjectStore, OTLP/Jaeger)
and the gotchas behind each, see [viewing-events.md](viewing-events.md).

## See also

- [`PodTraceSession`](crd-podtracesession.md) — the bounded session CR
  that schedules materialise on every run.
- [`ExporterConfig`](crd-exporterconfig.md) — required by every session
  the schedule runs.
- [Viewing Events](viewing-events.md) — the four ways to read captured events.
