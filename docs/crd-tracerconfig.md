# TracerConfig — cluster-wide infrastructure config

`TracerConfig` is cluster-scoped and singular. The operator looks up the
CR named `default` (or whatever a session's `spec.tracerConfigRef`
overrides) and uses it to drive the agent DaemonSet, session Job
template, and shared scheduling knobs.

When `helm install --set operator.enabled=true` runs with the chart
default (`tracerConfig.create=true`), a `default` TracerConfig is
rendered automatically — most users never touch this CR directly.

## Rendered by the chart

The chart's [`templates/tracerconfig.yaml`](../deploy/charts/podtrace/templates/tracerconfig.yaml)
populates the CR from `values.yaml`:

| values.yaml field | TracerConfig field |
|---|---|
| `image.repository` + `image.tag` | `spec.image` |
| `image.pullPolicy` | `spec.imagePullPolicy` |
| `image.pullSecrets` | `spec.imagePullSecrets` |
| `namespace.name` | `spec.systemNamespace` |
| `agent.resources` | `spec.agent.resources` |
| `agent.priorityClassName` | `spec.agent.priorityClassName` |
| `agent.eventBufferSize` | `spec.agent.eventBufferSize` |
| `agent.statusReportInterval` | `spec.agent.statusReportInterval` |
| `agent.btfMode` | `spec.btfMode` |
| `agent.nodeSelector` | `spec.nodeSelector` |
| `agent.tolerations` | `spec.tolerations` |
| `session.resources` | `spec.session.resources` |
| `session.ttlSecondsAfterFinished` | `spec.session.ttlSecondsAfterFinished` |
| `session.activeDeadlineSecondsOffset` | `spec.session.activeDeadlineSecondsOffset` |
| `session.backoffLimit` | `spec.session.backoffLimit` |
| `session.maxConcurrentSessionsPerNode` | `spec.maxConcurrentSessionsPerNode` |
| `tracerConfig.sidecarUploader` | `spec.session.sidecarUploader` |
| `tracerConfig.redaction` | `spec.redaction` |

To change a setting, prefer `helm upgrade --reuse-values --set …`
rather than editing the CR directly — direct edits get reverted on the
next chart upgrade.

## Spec reference

```yaml
apiVersion: podtrace.io/v1alpha1
kind: TracerConfig
metadata:
  name: default
spec:
  image: ghcr.io/gma1k/podtrace:0.14.1 # x-release-please-version
  imagePullPolicy: IfNotPresent
  systemNamespace: podtrace-system
  maxConcurrentSessionsPerNode: 2
  btfMode: auto                # auto | host | embedded
  nodeSelector: {}
  tolerations: []

  agent:
    priorityClassName: system-node-critical
    eventBufferSize: 10000
    statusReportInterval: 30s
    resources:
      requests: { cpu: 100m, memory: 128Mi }
      limits:   { cpu: 1,    memory: 512Mi }

  session:
    ttlSecondsAfterFinished: 300
    activeDeadlineSecondsOffset: 30
    backoffLimit: 0
    sidecarUploader: false
    resources:
      requests: { cpu: 100m, memory: 128Mi }
      limits:   { cpu: 1,    memory: 512Mi }
```

### Notable fields

- **`image`** — One container image serves all three runtime roles
  (operator, agent, CLI in session Jobs). Override at the chart level.
- **`btfMode`**:
  - `auto` (default): prefer `/sys/kernel/btf/vmlinux` when present,
    fall back to embedded stub types.
  - `host`: require `/sys/kernel/btf/vmlinux` (fails closed on minimal
    distros without BTF).
  - `embedded`: force the embedded stub even if host BTF is available.
- **`maxConcurrentSessionsPerNode`** — protects nodes from privileged
  Job pile-ups when many sessions land on the same node.
- **`session.sidecarUploader`** — opt-in native sidecar that re-uploads
  the report to `spec.reportRef`. Acts as a backup if the CLI crashes
  before its own self-upload completes. Requires Kubernetes 1.29+.
- **`redaction`** — PII scrubbing of event `Target`/`Details` before any
  exporter or report sink. `enabled` turns on the built-in rules
  (credentials, Bearer/Basic auth, JSON/YAML secrets, emails, card
  numbers); `redactDNSNames` additionally masks DNS query names;
  `customRules` adds regex rules (`name`, `pattern`, `replace`). Applies
  to both the agent DaemonSet and session Jobs. Off by default. See
  [language-runtime-adapters.md](language-runtime-adapters.md#pii-redaction).
- **`capture.headers`** — allowlist of up to 4 HTTP header names whose
  values are captured onto HTTP/2 and HTTP/3 events (appended to event
  `Details`, one `name: value` line each, values truncated at 64 bytes).
  Captured values pass through the redaction engine when `redaction` is
  enabled. See [http3.md](http3.md#header-allowlist-capture).

## Status reference

```yaml
status:
  desiredAgents: 3        # node count the DaemonSet targets
  readyAgents: 3          # agents currently passing readiness probe
  activeSessions: 1       # session Jobs currently Running
  conditions:
    - type: Reconciled
      status: "True"
      reason: Reconciled
    - type: Degraded
      status: "False"
  observedGeneration: 1
```

`activeSessions` lags `kubectl get jobs` by one reconcile tick — it's
read off Job status during the TracerConfig reconcile, not via a Job
informer.

## Common operations

```bash
# Inspect
kubectl get tracerconfig default -o yaml

# Bump event buffer size (full chart upgrade)
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values --set agent.eventBufferSize=50000

# Restrict agents to a subset of nodes
kubectl label node my-trace-node podtrace.io/enabled=true
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values --set 'agent.nodeSelector.podtrace\.io/enabled=true'

# Cap concurrent diagnose sessions per node
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values --set session.maxConcurrentSessionsPerNode=4
```

## Multiple TracerConfigs

Today only one TracerConfig is supported per cluster (named `default` by
the chart). Multiple TracerConfigs would result in multiple agent
DaemonSets fighting over the same `podtrace-agent` name; the operator
does not yet support per-TracerConfig DaemonSet naming.

If you need different settings for different node pools, use
`agent.nodeSelector` + `agent.tolerations` to scope a single agent
DaemonSet to specific pools.

## Related

- [operator.md](operator.md) — operator architecture
- [installation.md](installation.md) — Helm install
- [crd-podtrace.md](crd-podtrace.md) — continuous tracing
- [crd-podtracesession.md](crd-podtracesession.md) — bounded diagnose
