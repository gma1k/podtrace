# Migration: standalone CLI → CR-driven workflows

This guide is for users who already use the `podtrace` CLI binary and
want to adopt the operator/CRD model.

The CLI binary is **not deprecated**. It still works, and the operator
runs the same binary internally for session Jobs. This guide is about
adding declarative, multi-tenant, GitOps-friendly workflows on top —
not replacing the CLI.

## When to use which

| Use case | CLI | PodTrace CR | PodTraceSession CR |
|---|---|---|---|
| Quick interactive trace from a workstation | ✅ | | |
| Ad-hoc debugging by cluster admin | ✅ | | |
| Streaming events to a backend you can already see | ✅ | (when Phase 5+ lands events) | |
| Bounded diagnose with an artifact to share | ⚠️ requires manual export | | ✅ |
| Repeatable trace runs from CI / GitOps | | | ✅ |
| Multi-tenant: app team triggers a trace, no cluster admin | | | ✅ |
| Programmatic via `kubectl`/clientset | | ✅ | ✅ |
| Standardized RBAC scope | | ✅ | ✅ (per-session Role) |
| Audit trail (CR conditions, events) | | ✅ | ✅ |

CLI strengths the CRDs don't replace:
- Streaming events to your terminal in real time.
- Direct exec into a node-local privileged context.
- Independence from the operator (works on clusters without it).

## Quick translation table

### Real-time trace

```bash
# CLI
./bin/podtrace -n my-app my-pod
```

```yaml
# Continuous CR equivalent (control plane only today; events stubbed)
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata: { name: my-otlp, namespace: my-app }
spec:
  type: otlp
  otlp: { endpoint: otel:4318, protocol: http, insecure: true }
---
apiVersion: podtrace.io/v1alpha1
kind: PodTrace
metadata: { name: trace-my-pod, namespace: my-app }
spec:
  podRefs:
    - name: my-pod
  filters: [dns, net]
  exporterRef: { name: my-otlp }
```

For real eBPF event flow today, prefer the diagnose path below or run
the CLI directly via `kubectl exec` into an agent pod.

### Diagnose mode

```bash
# CLI
./bin/podtrace -n my-app my-pod --diagnose 30s --export json > report.json
```

```yaml
# CR equivalent — produces the same human-readable report in a ConfigMap
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata: { name: diag-my-pod, namespace: my-app }
spec:
  podRefs:
    - name: my-pod
  duration: 30s
  exporterRef: { name: my-otlp }
  reportRef:
    configMap: { name: my-pod-diag-report }
```

Then:

```bash
kubectl get cm my-pod-diag-report -n my-app -o jsonpath='{.data.report\.txt}' > report.txt
```

### Selector-driven multi-pod trace

```bash
# CLI (limited to one node)
./bin/podtrace -n my-app --pod-selector app=api --all-in-namespace
```

```yaml
# CR: fans out across every node hosting a matched pod
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata: { name: diag-api, namespace: my-app }
spec:
  selector:
    matchLabels:
      app: api
  duration: 5m
  exporterRef: { name: my-otlp }
```

### Tracing exporter

```bash
# CLI flags
--tracing --tracing-otlp-endpoint=otel:4318 --tracing-sample-rate=0.5
```

```yaml
# Equivalent ExporterConfig referenced from any PodTrace/PodTraceSession
spec:
  type: otlp
  otlp:
    endpoint: otel:4318
    protocol: http
  samplePercent: 50
```

## Step-by-step migration walkthrough

### 1. Install the operator alongside your existing CLI workflows

The operator runs in `podtrace-system` and does not affect users running
the CLI binary directly. Running both in parallel is fine.

```bash
helm install podtrace deploy/charts/podtrace \
  --namespace podtrace-system \
  --create-namespace \
  --set operator.enabled=true \
  --set image.tag=<your-built-tag>
```

After install, `kubectl get tracerconfig` shows a `default` CR and
`kubectl -n podtrace-system get ds podtrace-agent` shows the agent
DaemonSet running on every node.

See [installation.md](installation.md) for kind/cloud specifics.

### 2. Translate one CLI invocation to a CR

Pick a representative `podtrace --diagnose ...` command you run regularly.
Build a `PodTraceSession` that captures the same arguments and apply it.

The expected end-state from `kubectl get podtracesession` is `Completed`
within `duration + ~15s`, with `status.summary` and the `reportRef`
ConfigMap populated. If anything diverges from your CLI output, check
the [Troubleshooting](crd-podtracesession.md#troubleshooting) section.

### 3. Move scheduled diagnose runs into GitOps

Each `PodTraceSession` is a single CR — easy to template via Kustomize,
Helm, ArgoCD, etc. A common pattern:

- Commit one CR per scheduled run with `metadata.annotations.cron-schedule: '0 */4 * * *'`.
- Keep them in your app team's repo so engineers who own the workload
  also own its diagnose configuration.
- Pair with a CronJob that templates and applies the CR at the right times.

### 4. Tighten RBAC

In CLI mode, kicking off a trace requires either local privileged
access on a node or `kubectl exec` on a privileged pod. With the
operator, end users only need permission to create/read CRs in their
own namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: trace-runner
  namespace: my-app
rules:
  - apiGroups: ["podtrace.io"]
    resources: ["podtraces", "podtracesessions", "exporterconfigs"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["podtrace.io"]
    resources: ["podtraces/status", "podtracesessions/status"]
    verbs: ["get"]
```

Add a `RoleBinding` for the relevant SA / group / user. The operator's
own ClusterRole stays in `podtrace-system`; users never need privilege
escalation to run traces.

### 5. Decommission the CLI bash scripts (optional)

If you have wrapper scripts around the CLI in CI or developer machines,
swap them for `kubectl apply -f` of equivalent CRs. The advantage: the
CR shape is the same on every cluster, regardless of how the operator
was installed.

## Things to watch out for

**The CLI loads exporter config from flags or `--exporter-from-file`.**
The CR system stores it in an `ExporterConfig` CR. The session Job
mounts the operator-rendered bundle via the new `--exporter-from-file`
path. If you bake an `ExporterConfig` for each environment, your trace
manifest itself stays env-agnostic.

**Diagnose duration is a strict cap, not a minimum.** A CLI run with
`--diagnose 30s` can be Ctrl-C'd early and still produce a report.
Sessions run their full duration unless they fail.

**Sessions are one-shot.** Editing a Completed session has no effect.
Re-running means deleting and re-creating (or applying a new CR with a
different name).

**Cross-namespace exporter references are not supported.** Both the
ExporterConfig and the trace CR must live in the same namespace. To
share one OTLP collector across many app teams, copy the
`ExporterConfig` into each team's namespace.

**`PodTrace` events are not yet flowing through the agent.** Continuous
realtime tracing via the CR has working control-plane plumbing
(matching, status, RBAC) but events are stubbed (`NoopBackend`). For
real eBPF flow today, use `PodTraceSession` (works end-to-end) or stay
on the CLI.

## Related

- [operator.md](operator.md) — operator architecture
- [crd-podtrace.md](crd-podtrace.md) — continuous CR
- [crd-podtracesession.md](crd-podtracesession.md) — diagnose CR
- [crd-exporterconfig.md](crd-exporterconfig.md) — exporter setup
- [usage.md](usage.md) — original CLI usage guide
