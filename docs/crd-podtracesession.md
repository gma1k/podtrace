# PodTraceSession — bounded diagnose CR

`PodTraceSession` runs the same `podtrace --diagnose` workflow the CLI
exposes, but as one privileged Job per node hosting a matched pod. Each
Job runs for the requested duration, captures real eBPF events,
generates a human-readable report, and writes results back through three
parallel channels (kubelet termination message, optional sidecar
uploader, CLI self-upload to a ConfigMap or Secret).

This is the working end-to-end CR path today.

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
kind: PodTraceSession
metadata:
  name: diag-api
  namespace: my-app
spec:
  selector:
    matchLabels:
      app: api
  duration: 30s
  filters: [dns, net]
  exporterRef:
    name: prod-otlp
  reportRef:
    configMap:
      name: api-diag-report
```

## Spec reference

| Field | Type | Required | Notes |
|---|---|---|---|
| `selector` | LabelSelector | one of selector/podRefs | Pods labeled to diagnose. |
| `podRefs` | `[{namespace, name}]` | one of selector/podRefs | Explicit pod list. |
| `namespaceSelector` | LabelSelector | optional | Widens `selector` across namespaces. |
| `containerName` | string | optional | Restrict to one container per pod. |
| `duration` | Go duration string | required | Wall-clock run time, e.g. `"30s"`, `"5m"`. Webhook rejects `0s` and bounded by `TracerConfig.spec.session.maxDuration`. |
| `filters` | `[dns,net,fs,cpu,proc]` | optional | Event categories to record. |
| `exporterRef.name` | string | required | Names an `ExporterConfig` in the same namespace. |
| `samplePercent` | int 0-100 | optional | Workload-owner sampling intent. The operator combines this with `ExporterConfig.spec.samplePercent` (platform-owner cap) and writes the **minimum** of the two to the session bundle. Unset on either side is treated as 100%. The resolved value is echoed at `status.policy.effectiveSampleRate`. |
| `reportRef` | object | optional | Persistent artifact sink — see "Report sinks" below. |
| `ttlSecondsAfterFinished` | int | optional | When to GC the CR after Completed/Failed (default 300). |
| `thresholds.errorRatePercent` | int 0-100 | optional | The session Job tags spans for events carrying a non-zero error code; identical semantics to [PodTrace thresholds](crd-podtrace.md#spec-reference). |
| `thresholds.rttSpikeMs` | int ≥0 | optional | Tag network-latency spans whose source event latency exceeds this threshold. |
| `thresholds.fsSlowMs` | int ≥0 | optional | Tag FS spans whose source event latency exceeds this threshold. |

Per-session policy is also surfaced on `status.policy` (`effectiveSampleRate`,
`filters`, `thresholds`, `generation`, `hash`) with the same semantics as
[PodTrace.status.policy](crd-podtrace.md#status-reference).

## Report sinks

`spec.reportRef` controls where the full human-readable report lands at
end of diagnose. Mutually exclusive with itself — exactly one of:

| Field | What it produces |
|---|---|
| `configMap.name` | A ConfigMap in the session's namespace. Each traced node writes its report under a per-node key `data["report-<node>.txt"]` (so multi-node sessions don't overwrite each other). The CLI patches it via a per-session Role + RoleBinding scoped to that exact name. Capped at the etcd ConfigMap limit (~1MiB). |
| `secret.name` | A Secret in the session's namespace, same per-node `data["report-<node>.txt"]` keys as the ConfigMap sink. Use this when the report may carry sensitive data (private hostnames, paths, payloads). Same size cap as ConfigMap. |
| `objectStore` | Uploads to an S3-, GCS-, or Azure-Blob–compatible bucket via a [native sidecar](object-store-reports.md). The only sink that escapes the etcd object-size limit. Requires `TracerConfig.spec.session.sidecarUploader=true` and either ambient cloud credentials (IRSA / Workload Identity / Managed Identity) or an explicit `credentialsSecretRef`. |

When `reportRef` is unset, only the exporter receives event spans and
the session status keeps the small inline summary.

## Three parallel artifact channels

The CLI emits results through three channels so the operator and users
can introspect a finished session without scraping pod logs:

1. **Termination message** — kubelet captures a compact JSON the CLI
   writes to `/dev/termination-log` (≤4KB). The operator reads it from
   `Pod.Status.ContainerStatuses[].State.Terminated.Message` and
   populates `status.summary` + `status.jobs[].eventCount`.
2. **CLI self-upload** — the CLI directly patches the configured
   `reportRef.configMap` or `.secret` using a narrow per-session
   RoleBinding granting `get/update/create` on exactly that object.
3. **Sidecar uploader (opt-in)** — when `TracerConfig.spec.session.sidecarUploader=true`,
   the Job runs a native sidecar (k8s 1.29+ init container with
   `restartPolicy: Always`) that re-uploads the report on main-container
   termination. Belt-and-suspenders backup if the CLI crashes.

## Status reference

| Field | Notes |
|---|---|
| `state` | `Pending` → `Running` → `Completed` / `Failed`. |
| `startTime`, `completionTime` | Set when the first Job starts and last completes. |
| `jobs[]` | One entry per node hosting a matched pod. Carries `node`, `name`, `completed`, `eventCount`, `startTime`, `completionTime`. |
| `summary` | Aggregated `{totalEvents, dnsEvents, netEvents, fsEvents, cpuEvents, procEvents, errorsDetected}` across all Jobs. |
| `conditions` | Standard `Reconciled`, `Degraded`. |

## Lifecycle

```
applied → Pending → (Running once first Job starts)
                  → Completed (all Jobs Succeeded) | Failed (any Job fails past backoff)
                  → CR auto-deleted after .spec.ttlSecondsAfterFinished (default 300s)
```

The session is one-shot: terminal states are sticky. Editing a
Completed session has no effect — create a new CR.

## Common operations

```bash
# Run a 30s diagnose against pods labeled app=api
kubectl apply -f my-session.yaml

# Watch
kubectl get podtracesession diag-api -n my-app -w

# Get aggregated summary
kubectl get podtracesession diag-api -n my-app -o jsonpath='{.status.summary}{"\n"}'

# Per-node breakdown
kubectl get podtracesession diag-api -n my-app -o jsonpath='{range .status.jobs[*]}{.node}: {.eventCount} events{"\n"}{end}'

# Read the full report
kubectl get cm api-diag-report -n my-app -o jsonpath='{.data.report\.txt}' | less

# Inspect raw kubelet termination message
kubectl -n podtrace-system get pods -l podtrace.io/session=diag-api \
  -o jsonpath='{range .items[*]}{.spec.nodeName}: {.status.containerStatuses[?(@.name=="podtrace")].state.terminated.message}{"\n"}{end}'

# Force-delete (finalizer cleans up Job + bundle + per-session RBAC)
kubectl delete podtracesession diag-api -n my-app
```

## What the operator creates per session

- **In `podtrace-system`:**
  - One Job per node (`pts-<sessionUID>-<nodeHash>`)
  - Bundle ConfigMap (`pts-bundle-<sessionUID>`) carrying the rendered
    exporter config, mounted into Jobs at `/etc/podtrace/exporter/`
  - Companion Secret (same name) when the ExporterConfig has credentials
- **In the user namespace:**
  - `Role podtrace-session-report-<sessionUID>` granting `get/update/create`
    on the specific `reportRef.ConfigMap` or `.Secret`
  - `RoleBinding podtrace-session-report-<sessionUID>` binding the role
    to the system-NS `podtrace-session` ServiceAccount

All five objects are tied to the session via the
`podtrace.io/cleanup` finalizer; deleting the CR reaps them.

## Multi-node behavior

The selector resolves cluster-wide; the operator fans out one Job per
node with at least one matched pod. Each Job runs independently — they
do not coordinate. The aggregated `status.summary` adds counts across
all Jobs.

## RBAC produced for the session Job

The session Job runs as the narrow `podtrace-session` SA (not the agent
SA). Its grants:

| Verb | Resource | Scope |
|---|---|---|
| `get`, `list`, `watch` | `pods` | session namespace |
| `get`, `update` | `configmaps` or `secrets` | exact `reportRef` name only |
| `create` | `configmaps` or `secrets` | session namespace (Kubernetes splits create from update) |

Cluster-wide pod read, cluster-wide secret read, and access to other
ConfigMaps in the namespace are **not** granted. The session SA cannot
exfiltrate any sink other than its own.

## Constraints

- **One bundle per session.** Bundles are keyed by session UID. Editing
  the upstream `ExporterConfig` does not retroactively change a
  Completed session's bundle.
- **Webhook validation.** A webhook rejects `duration <= 0`, missing
  `exporterRef`, both selector AND podRefs set, or a malformed
  `reportRef.objectStore.uri`. Well-formed objectStore URIs are
  accepted — see [Object-store report sinks](object-store-reports.md).
- **Webhook needs the operator running.** Sessions cannot be applied
  while the operator is down (webhook callout fails).
- **Sample workloads.** A `pause:3.9` pod produces no events. Use
  workloads that actually do something (curl in a loop, an HTTP server,
  a DB-driven service) to see meaningful counts in the report.

## Troubleshooting

**Phase stuck `Pending` past 10s:**
```bash
kubectl describe podtracesession <name> -n <ns>
```
Look at the `Conditions` block. Likely candidates:
- `Degraded=True ExporterNotFound` — fix the `exporterRef`.
- `Degraded=True NodeCapacity` — `TracerConfig.spec.maxConcurrentSessionsPerNode` saturated.
- No matched pods — selector matches no `Running` pods.

**Phase = `Failed` immediately:**
```bash
kubectl -n podtrace-system get pods -l podtrace.io/session=<name> \
  -o jsonpath='{.items[*].status.containerStatuses[0].state.terminated.message}{"\n"}'
kubectl -n podtrace-system logs -l podtrace.io/session=<name> --tail=200
```
Most common: missing kernel BTF, eBPF verifier rejection, or the cgroup
safety check failing on a non-standard kubelet layout
(set `PODTRACE_ALLOW_BROAD_CGROUP=1` via `TracerConfig.spec.session` if
you've verified the layout is safe).

**Phase = `Completed` but `summary.totalEvents=0`:**
The workload was idle during the diagnose window. Check pod activity
during the run; consider increasing `duration`.

**Report ConfigMap empty:**
The CLI reached end-of-diagnose but failed to upload. Check Job logs
for `emit session artifacts` warnings. Likely a transient apiserver
error; the next run will succeed.

## Related

- [crd-podtrace.md](crd-podtrace.md) — continuous tracing CR
- [crd-exporterconfig.md](crd-exporterconfig.md) — exporter setup
- [operator.md](operator.md) — operator architecture
