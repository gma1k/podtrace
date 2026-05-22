# Podtrace Operator

The podtrace operator runs the same eBPF-based tracing podtrace's CLI binary
already provides, but driven through Kubernetes Custom Resources. Instead of
SSHing to a node or `kubectl exec`-ing a privileged pod, users `kubectl apply`
a CR; the operator and an agent DaemonSet handle the rest.

## Architecture at a glance

```
                       +---------------------------+
                       | podtrace operator         |
                       | (Deployment in            |
                       |  podtrace-system)         |
                       +---------------------------+
                                | reconciles
        +-----------------------+-----------------------+
        |                       |                       |
        v                       v                       v
  +------------+         +-------------+         +--------------+
  | TracerCfg  |         | PodTrace    |         | PodTraceSess |
  | (cluster)  |         | (continuous |         | (bounded     |
  |            |         |  realtime)  |         |  diagnose)   |
  +-----+------+         +------+------+         +------+-------+
        |                       |                       |
        v                       v                       v
  podtrace-agent          exporter bundle         per-node Job
  DaemonSet               (CM + Secret in         under
  (one pod / node)        podtrace-system)        podtrace-system
```

Three reconcilers, each owning one CRD:

- **TracerConfigReconciler** — manages cluster-wide infrastructure: the agent
  ServiceAccount + RBAC (cluster-wide ClusterRole + namespaced Role for bundle
  reads in `podtrace-system`), the agent DaemonSet, and the session SA.
- **PodTraceReconciler** — continuous tracing CR. Materializes an exporter
  bundle in `podtrace-system` for each PodTrace, watches per-node status from
  agents, and aggregates `status.nodeStatus` rollups.
- **PodTraceSessionReconciler** — bounded diagnose CR. Spawns one privileged
  Job per node hosting a matched pod, mounts the exporter bundle into the
  Job, and reads kubelet termination messages for `status.summary`.

## What runs where

| Component | Where | Privilege | Notes |
|---|---|---|---|
| Operator Deployment | `podtrace-system` | Unprivileged, runAsNonRoot=65532, readOnly rootfs, `drop: ["ALL"]` | Single replica with leader election. |
| Agent DaemonSet | `podtrace-system`, every node | Privileged: CAP_BPF + CAP_SYS_ADMIN + CAP_PERFMON, hostPID, hostPath mounts | One pod per node hosts long-lived eBPF probes + status writers. |
| Session Job | `podtrace-system`, pinned to one node | Same caps as agent | Created on demand by the session reconciler. TTL'd 300s after Completed. |
| Validating webhook | Inside operator pod (port 9443) | Inherits operator's unprivileged context | TLS via cert-manager (default) or external. |

## Custom Resources

| CRD | Scope | Purpose | Doc |
|---|---|---|---|
| [`TracerConfig`](crd-tracerconfig.md) | Cluster | Image, agent runtime defaults, session caps. One per cluster, named `default`. | crd-tracerconfig.md |
| [`ExporterConfig`](crd-exporterconfig.md) | Namespace | Reusable exporter destination (OTLP, Jaeger, Zipkin, Splunk, DataDog). | crd-exporterconfig.md |
| [`PodTrace`](crd-podtrace.md) | Namespace | Continuous tracing of pods matching a selector. | crd-podtrace.md |
| [`PodTraceSession`](crd-podtracesession.md) | Namespace | Bounded diagnose-mode trace producing a report artifact. | crd-podtracesession.md |

## Install via Helm

For a public release:

```bash
helm install podtrace oci://ghcr.io/gma1k/charts/podtrace --version 0.1.0 \
  --namespace podtrace-system --create-namespace \
  --set operator.enabled=true
```

For a custom build of this checkout:

```bash
helm install podtrace deploy/charts/podtrace \
  --namespace podtrace-system \
  --create-namespace \
  --set operator.enabled=true \
  --set image.tag=<your-built-tag>
```

This single install renders the CRDs, the namespace (with PSA `enforce:
privileged`), the operator Deployment, agent ClusterRole + namespaced bundle
Role, and a default `TracerConfig` CR — which the TracerConfigReconciler
picks up and uses to roll out the agent DaemonSet automatically.

See [installation.md](installation.md) for prerequisites, kind/cluster
specifics, and webhook TLS setup.

## Key invariants

- **`podtrace-system` is the only PSA-privileged namespace.** All raw eBPF
  pods land here. User namespaces stay PSA-restricted.
- **Cross-namespace bundles avoid Kubernetes' namespaced-owner forbidding.**
  ConfigMaps/Secrets/Jobs the operator creates in `podtrace-system` on
  behalf of a user-namespace CR cannot use ownerReferences (Kubernetes
  forbids cross-namespace owner refs for namespaced resources). Cleanup
  goes through `podtrace.io/cleanup` finalizers + label selectors instead.
- **Per-session RBAC is scoped to one named ConfigMap or Secret.** The
  session ServiceAccount can patch only the specific `spec.reportRef`
  object — not arbitrary objects in the user namespace.
- **Server-Side Apply for status writes.** Multiple agents patch the same
  PodTrace's `status.nodeStatus` array concurrently; SSA with per-node
  `FieldOwner` keeps them from clobbering each other.

## Observability

Operator and agent both expose Prometheus metrics:

- **Operator** — `/metrics` on port 8080 in the operator pod. Standard
  controller-runtime metrics (workqueue depth, reconcile latency, error rate).
- **Agent** — `/metrics` on port 9090 in each agent pod. Per-CR event
  counters, dropped-event counters, active-cgroup gauge, reconcile counter,
  and `podtrace_agent_backend_degraded{reason=...}` — set to `1` if the
  agent failed to load the real eBPF backend and is running in noop
  fallback mode. Healthy agents emit no `backend_degraded` series; alert
  on `max by(node)(podtrace_agent_backend_degraded) > 0` and the `reason`
  label routes to remediation (`permission_denied`, `btf_unavailable`,
  `kernel_too_old`, `collection_failed`, `ringbuf_failed`,
  `map_lookup_failed`, `invalid_event`, `unknown`).

  Policy-wiring observability (one series per CR):

  - `podtrace_agent_effective_sample_rate{cr_namespace,cr_name}` — the
    sample rate (0.0–1.0) the agent is actually applying, after the
    operator-side min(CR, ExporterConfig) resolution.
  - `podtrace_agent_policy_generation{cr_namespace,cr_name}` —
    `metadata.generation` of the source CR at bundle-read time. Compare
    against the CR's live generation to detect bundle-propagation lag.
  - `podtrace_agent_threshold_tripped_total{cr_namespace,cr_name,threshold}` —
    counter, bumped once per event that exceeds a configured threshold
    (`threshold ∈ {fs_slow, rtt_spike, error_rate}`). Stateless per-event
    evaluation: a counter delta over a window is the trip frequency
    directly.

Enable scrape configs via Helm:

```bash
helm upgrade podtrace ... \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.podMonitor.enabled=true
```

Both templates are gated on `monitoring.coreos.com/v1` being installed —
flipping the toggle on a cluster without prometheus-operator is a silent
no-op rather than a hard install failure.

Both [PodTrace](crd-podtrace.md) (continuous) and
[PodTraceSession](crd-podtracesession.md) (bounded) drive the real eBPF
backend by default, with events surfacing as OpenTelemetry spans on the
configured exporter. Session reports can also be uploaded directly to
S3-, GCS-, or Azure-Blob–compatible object stores — see
[Object-store report sinks](object-store-reports.md).

## Going further

- [Installation](installation.md) — prerequisites, Helm install, kind setup
- [PodTrace CR](crd-podtrace.md) — continuous tracing reference
- [PodTraceSession CR](crd-podtracesession.md) — bounded diagnose reference
- [Migration](migration.md) — moving from CLI to CR-driven workflows
- [Architecture](architecture.md) — internals of the tracer itself
