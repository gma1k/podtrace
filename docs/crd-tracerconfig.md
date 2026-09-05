# TracerConfig — agent fleet infrastructure config

`TracerConfig` is cluster-scoped. Each one owns an **agent fleet**: a
DaemonSet, its ServiceAccount and RBAC, and the template for the session
Jobs the operator spawns.

Most clusters need exactly one, named `default`. A cluster with several
node pools that need different images, resource envelopes or capture
policies can run one TracerConfig per pool — see
[Multiple TracerConfigs](#multiple-tracerconfigs).

When `helm install --set operator.enabled=true` runs with the chart
default (`tracerConfig.create=true`), a `default` TracerConfig is
rendered automatically — most users never touch this CR directly.

## Rendered by the chart

The chart's
[`templates/cr-bootstrap.yaml`](../deploy/charts/podtrace/templates/cr-bootstrap.yaml)
applies the CR from `values.yaml` via a post-install hook Job:

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
| `session.activeDeadlineOffset` | `spec.session.activeDeadlineOffset` |
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
  image: ghcr.io/gma1k/podtrace:0.14.8 # x-release-please-version
  imagePullPolicy: IfNotPresent
  systemNamespace: podtrace-system
  maxConcurrentSessionsPerNode: 2
  btfMode: auto                # auto | host | embedded
  nodeSelector: {}
  tolerations: []
  fleetPriority: 0             # tie-break when fleets overlap

  agent:
    priorityClassName: system-node-critical
    eventBufferSize: 10000
    statusReportInterval: 30s
    resources:
      requests: { cpu: 100m, memory: 128Mi }
      limits:   { cpu: 1,    memory: 512Mi }

  session:
    ttlSecondsAfterFinished: 300
    activeDeadlineOffset: 30s
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
- **`fleetPriority`** — orders fleets that target the same node. Advisory:
  it decides what the `Conflict` condition reports, not which agent
  runs. See [Multiple TracerConfigs](#multiple-tracerconfigs).
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
  matchedNodes: 3         # nodes this fleet's constraints select
  contestedNodes: 0       # of those, how many another fleet also selects
  conditions:
    - type: Reconciled
      status: "True"
      reason: Reconciled
    - type: Degraded
      status: "False"
    - type: Conflict
      status: "False"
      reason: ExclusiveNodes
  observedGeneration: 1
```

`activeSessions` lags `kubectl get jobs` by one reconcile tick — it's
read off Job status during the TracerConfig reconcile, not via a Job
informer.

`contestedNodes` > 0 means another fleet claims some of the same nodes
and their events are counted twice; see
[Overlapping fleets](#overlapping-fleets). `Conflict=Unknown` with
reason `NodesUnreadable` means the operator cannot list Nodes, so
overlap is simply unknown — everything else still reconciles.

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

A cluster can run several TracerConfigs. Each owns a separate agent
fleet, so different node pools can run different images, resource
envelopes, or capture and redaction policies.

**Fleets must select disjoint node sets.** A node covered by two fleets
runs two agents, both attach their eBPF programs, and every event on
that node is exported twice — once per fleet.

### Object names

Each fleet's objects are suffixed with its TracerConfig name. The config
named `default` keeps the unsuffixed legacy names, so upgrading a
single-config cluster does not recreate anything:

| TracerConfig | DaemonSet / ServiceAccount / ClusterRole |
|---|---|
| `default` | `podtrace-agent` |
| `gpu-pool` | `podtrace-agent-gpu-pool` |

Because the name becomes the value of the `podtrace.io/tracer-config`
label on the DaemonSet's (immutable) pod selector, TracerConfig names
are limited to 63 characters.

### Example: two node pools

```yaml
apiVersion: podtrace.io/v1alpha1
kind: TracerConfig
metadata:
  name: general
spec:
  image: ghcr.io/gma1k/podtrace:0.14.8 # x-release-please-version
  nodeSelector:
    workload: general
---
apiVersion: podtrace.io/v1alpha1
kind: TracerConfig
metadata:
  name: regulated
spec:
  image: ghcr.io/gma1k/podtrace:0.14.8 # x-release-please-version
  nodeSelector:
    workload: regulated
  redaction:
    enabled: true
    redactDNSNames: true
```

The chart renders only one TracerConfig. Apply additional ones with
`kubectl apply`, or set `tracerConfig.create=false` and manage all of
them yourself.

Session Jobs follow the same fleets. A `PodTraceSession` spawns one Job
per node, and each Job takes the image, resources and redaction policy of
the fleet targeting *its* node — so a session whose pods span two pools
runs under each pool's own policy. Pin the whole session to one config
with `spec.tracerConfigRef`. See
[crd-podtracesession.md](crd-podtracesession.md#tracerconfig-resolution).

### Overlapping fleets

Overlap depends on how nodes are labelled, not on how the two specs
compare: `{pool: a}` and `{zone: eu-1}` both match a node carrying both
labels, and two fleets that are disjoint today start colliding the
moment someone relabels a node. So podtrace detects overlap
continuously rather than rejecting it once at admission.

**The operator reports overlap; it does not resolve it.** Both
DaemonSets keep running on a contested node. What you get is:

- `status.matchedNodes` and `status.contestedNodes` on each TracerConfig
- a `Conflict` condition naming the contested nodes and the rival config
- `podtrace_operator_tracerconfig_contested_nodes`, and
  `count by (node) (podtrace_agent_info) > 1` from the agents

```console
$ kubectl get tracerconfig
NAME        DESIRED   READY   SESSIONS   AGE
general     3         3       0          5m
regulated   2         2       0          5m

$ kubectl describe tracerconfig regulated | grep -A3 Conflict
  Type:     Conflict
  Status:   True
  Reason:   OverlappingNodes
  Message:  shares node(s) node-7 with TracerConfig general; this config
            has highest priority on 0 of them. …
```

`spec.fleetPriority` (higher wins; ties broken by the older
`creationTimestamp`, then by name) records which fleet *should* own a
contested node. It is advisory today — it decides what the Conflict
condition reports, nothing more.

Admission rejects only the collisions that hold regardless of node
labels: a second TracerConfig with no `nodeSelector` and no required
`nodeAffinity` (which would target every node), and a `nodeSelector`
identical to an existing config's. Anything subtler comes back as a
warning at apply time and as the `Conflict` condition afterwards.

### RBAC

Overlap detection reads Nodes, so the operator's ClusterRole includes
`nodes: get, list, watch`. It is read-only — podtrace never writes to a
Node. On an upgrade where the operator image is newer than its
ClusterRole, overlap detection reports `Conflict=Unknown` with reason
`NodesUnreadable` and everything else reconciles normally.

## Related

- [operator.md](operator.md) — operator architecture
- [installation.md](installation.md) — Helm install
- [crd-podtrace.md](crd-podtrace.md) — continuous tracing
- [crd-podtracesession.md](crd-podtracesession.md) — bounded diagnose
