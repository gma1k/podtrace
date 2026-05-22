# PodTrace — continuous tracing CR

`PodTrace` declares a continuous tracing intent against a set of pods. The
operator creates an exporter bundle in `podtrace-system`, the agent
DaemonSet matches the selector, and per-node status entries roll up into
the CR's `.status.nodeStatus` array.

The agent loads the real eBPF backend by default and emits one
OpenTelemetry span per kernel event to the configured exporter. A
no-op backend remains available for clusters where loading eBPF
programs is undesirable — opt in by passing `--backend=noop` to the
agent (DaemonSet-template override; production deployments leave this
unset).

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
kind: PodTrace
metadata:
  name: watch-api
  namespace: my-app
spec:
  selector:
    matchLabels:
      app: api
  filters: [dns, net]
  exporterRef:
    name: prod-otlp
```

## Spec reference

| Field | Type | Required | Notes |
|---|---|---|---|
| `selector` | LabelSelector | one of selector/podRefs | Pods labeled to trace. Empty selector is rejected. |
| `podRefs` | `[{namespace, name}]` | one of selector/podRefs | Explicit pod list. Cross-namespace allowed. |
| `namespaceSelector` | LabelSelector | optional | Widens `selector` across namespaces. Field's expressions are not yet evaluated; presence alone enables cluster-wide search. |
| `filters` | `[dns,net,fs,cpu,proc]` | optional | Empty = all categories. Agents enforce the set per-event in userspace and only the listed categories reach the configured exporter. |
| `exporterRef.name` | string | required | Names an `ExporterConfig` in the same namespace. |
| `paused` | bool | optional | Stop emitting events without deleting the CR. |
| `samplePercent` | int 0-100 | optional | Workload-owner sampling intent. The operator combines this with `ExporterConfig.spec.samplePercent` (platform-owner cap) and writes the **minimum** of the two to the bundle — that minimum is what every exporter applies. Unset on either side is treated as 100%. The resolved value is echoed at `status.policy.effectiveSampleRate`. |
| `thresholds.errorRatePercent` | int 0-100 | optional | When set, the agent stamps `podtrace.threshold.error_rate.observed=true` on every span whose source event carries a non-zero error code and bumps `podtrace_agent_threshold_tripped_total{threshold="error_rate"}`. |
| `thresholds.rttSpikeMs` | int ≥0 | optional | When set, the agent tags spans whose source event latency exceeds this threshold (Connect/TCPSend/TCPRecv/UDPSend/UDPRecv) and bumps `podtrace_agent_threshold_tripped_total{threshold="rtt_spike"}`. |
| `thresholds.fsSlowMs` | int ≥0 | optional | When set, the agent tags FS-event spans (Open/Read/Write/Close/Fsync/Unlink/Rename) whose latency exceeds the threshold and bumps `podtrace_agent_threshold_tripped_total{threshold="fs_slow"}`. |

## Status reference

| Field | Notes |
|---|---|
| `matchedPods` | Sum of `activeCgroups` across all reporting nodes. |
| `nodeStatus[]` | One entry per node hosting a matched pod. Each carries `node`, `ready`, `activeCgroups`, `eventsTotal`, `droppedEvents`, `lastHeartbeat`, `message`, and `policyHash` (the hash of the bundle the agent last observed — see "Verifying policy propagation" below). |
| `conditions` | Standard Kubernetes condition objects. `Ready=True` once at least one node reports healthy. `Degraded=True` on bundle sync errors. `Paused` mirrors `spec.paused`. `PolicyApplied=True` once the operator has resolved `spec.filters`/`spec.samplePercent`/`spec.thresholds` and written them to the bundle. |
| `observedGeneration` | Most recent generation reconciled. |
| `policy.effectiveSampleRate` | The operator-resolved sample rate (0–100), already reduced to the minimum of `spec.samplePercent` and `ExporterConfig.spec.samplePercent`. This is what every agent and exporter actually applies — do not infer effective sampling from `spec` alone. |
| `policy.filters` | Sorted, deduplicated copy of `spec.filters` written to the bundle. |
| `policy.thresholds` | Echo of `spec.thresholds` written to the bundle. |
| `policy.generation` | `metadata.generation` of the CR at bundle-write time. Pair with `nodeStatus[].policyHash` to verify propagation reached every node. |
| `policy.hash` | sha256 over the bundle's policy fields. Two CRs with identical filters/sample/thresholds produce the same hash regardless of exporter. |

### Verifying policy propagation

`status.policy.hash` is what the operator wrote; each
`status.nodeStatus[].policyHash` is what that node's agent observed. When
they agree, the bundle has propagated:

```bash
kubectl get podtrace watch-api -n my-app -o jsonpath='
status.policy.hash = {.status.policy.hash}{"\n"}
{range .status.nodeStatus[*]}{.node}: {.policyHash}{"\n"}{end}'
```

A node showing an empty or stale hash means the agent has not yet
re-read the bundle ConfigMap — usually a transient state during edits.

## Multi-CR merging on shared targets

Two `PodTrace` CRs targeting overlapping pods produce **one** tracer
process per node. The agent merges:

- **CgroupIDs** — union, so the kernel-side filter admits any matched pod.
- **Filters** — union, so the agent emits any event type any CR cares about.
- **Exporters** — per-CR dispatch table, so each CR's events land on its
  own exporter (router filters by event type per CR).

Result: overlapping CRs share kernel resources, do not double-trace, and
each independently reports `eventsTotal` on its own `nodeStatus`.

## Common operations

```bash
# Apply
kubectl apply -f my-podtrace.yaml

# Watch reconcile
kubectl get podtraces.podtrace.io -A -w

# Inspect per-node rollup
kubectl get podtrace watch-api -n my-app -o jsonpath='{range .status.nodeStatus[*]}{.node}: ready={.ready} events={.eventsTotal}{"\n"}{end}'

# Pause without deleting
kubectl patch podtrace watch-api -n my-app --type=merge -p '{"spec":{"paused":true}}'

# Resume
kubectl patch podtrace watch-api -n my-app --type=merge -p '{"spec":{"paused":false}}'

# Delete (finalizer cleans up the bundle in podtrace-system)
kubectl delete podtrace watch-api -n my-app
```

## RBAC

Continuous CRs do not require any extra user-namespace RBAC beyond what
the operator's ClusterRole already grants. The exporter `Secret` (when
the bundle has credentials) lives in the user namespace and the operator
reads it during reconcile; agents only read the operator-materialized
bundle in `podtrace-system`.

## Troubleshooting

**`status.nodeStatus` is empty:** The agent DaemonSet hasn't reported
yet, OR no node has a matched pod. Check:

```bash
kubectl get pods -n my-app -l <your-selector>
kubectl -n podtrace-system get pods -l podtrace.io/component=agent
```

**`Degraded=True ExporterNotFound`:** The named ExporterConfig isn't in
the same namespace. Cross-namespace exporter references are not allowed.

**`Degraded=True BundleSync`:** The operator failed to materialize the
exporter bundle in `podtrace-system`. Likely a missing user-namespace
Secret referenced by the ExporterConfig. Check the operator log.

**Events stay at zero:** The agent matched no pods, the matched pods
generate no kernel events of the configured `filters`, or
`podtrace_agent_backend_degraded` is non-zero on the agent's node
(check `kubectl -n podtrace-system logs daemonset/podtrace-agent` for
the failure reason). The continuous CR uses the real eBPF backend by
default — confirm with
`kubectl -n podtrace-system get ds podtrace-agent -o jsonpath='{.spec.template.spec.containers[0].args}'`
that `--backend=noop` is not present.

## Related

- [crd-podtracesession.md](crd-podtracesession.md) — bounded diagnose CR for one-shot traces
- [crd-exporterconfig.md](crd-exporterconfig.md) — exporter setup
- [operator.md](operator.md) — operator architecture
