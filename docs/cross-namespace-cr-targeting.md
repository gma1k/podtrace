# Cross-namespace targeting via `namespaceSelector`

`PodTrace` and `PodTraceSession` both accept a `spec.namespaceSelector`.
Without it, the CR's `spec.selector` is evaluated only inside the CR's
own namespace. With it, the operator resolves the label expression
against every namespace in the cluster and applies the resulting
**allowlist** to pod matching.

> **Cross-namespace tracing is opt-in from the target side.** A CR may
> only trace pods in a *foreign* namespace when that namespace grants
> access via the `podtrace.io/allow-tracing-from` annotation (see
> [Target-namespace consent](#target-namespace-consent-required)).
> Without the grant, foreign namespaces are silently excluded from the
> allowlist, a CR can never reach another team's traffic just by
> naming their namespace. This is the tenancy boundary.

This page covers when to use it, exactly how the allowlist is
resolved, what shows up on `.status`, and the RBAC / lifecycle
implications. For the CLI multi-pod analogue see
[multi-pod-tracing.md](multi-pod-tracing.md).

## TL;DR

```yaml
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata: { name: prod-diag, namespace: observability }
spec:
  selector:
    matchLabels: { app: api }            # which pods inside each allowed ns
  namespaceSelector:
    matchLabels: { tier: prod }          # which namespaces the selector runs against
  duration: 30s
  filters: [dns, net, fs]
  exporterRef: { name: prod-otlp }
```

Result: every `Running` pod labeled `app=api` in any namespace labeled
`tier=prod` is matched. The session lives in `observability`; the
matched pods live elsewhere.

## When you actually need it

| Situation | namespaceSelector? |
|---|---|
| All target pods are in the same namespace as the CR | unset (default) |
| Multiple app namespaces share a label (`tier=prod`, `region=eu`, `owner=team-x`) and you want one CR per group | use it |
| Cluster-wide trace (every namespace) | `matchExpressions: [{key: kubernetes.io/metadata.name, operator: Exists}]` — but consider scope of the privilege first |

`spec.selector` is required regardless; `namespaceSelector` only
extends *where* the pod selector is evaluated.

## Target-namespace consent (required)

A namespaced CR living in namespace **A** carries the authority of
whoever can `create` that CR in **A**. Left unchecked, that authority
would extend into any namespace **B** the CR names, the operator holds
cluster-wide RBAC and would happily provision pod-read access in **B**
and spawn a privileged eBPF Job that captures **B**'s decrypted L7
payloads, DNS, syscalls, and file paths. That is a cross-tenant
interception primitive, and the decision to allow it belongs to the
owner of the **target** namespace, not the CR author.

Podtrace therefore follows the [Gateway API ReferenceGrant][refgrant]
model: **the target namespace must opt in**. Annotate namespace **B**:

```bash
# Allow CRs from the "observability" namespace to trace this namespace
kubectl annotate ns team-b podtrace.io/allow-tracing-from=observability

# Allow a specific set of source namespaces
kubectl annotate ns team-b podtrace.io/allow-tracing-from=observability,platform-ops

# Allow every namespace (use deliberately)
kubectl annotate ns team-b podtrace.io/allow-tracing-from='*'
```

Rules:

- A namespace **always** allows tracing from CRs in **its own**
  namespace — no annotation needed for same-namespace tracing.
- The annotation value is a comma-separated list of source namespace
  names, or `*` for any. Whitespace around entries is ignored; an empty
  or whitespace-only value grants nothing.
- Matching is exact per entry — `observer` does **not** match
  `observer-2` or `the-observer-ns`.
- The check runs at **every reconcile**, so revoking the grant (or
  deleting the annotation) stops an in-flight continuous trace on the
  next reconcile, and grants added after the CR was created take effect
  without recreating the CR.
- `spec.podRefs` naming an ungranted foreign namespace are **rejected at
  admission** (the webhook) and dropped at reconcile (the operator).
  `spec.namespaceSelector` matches in ungranted namespaces are
  **excluded** from the allowlist; the webhook emits a warning rather
  than an error because the selector is dynamic.

The enforcement is defense-in-depth: the validating webhook gives fast
admission feedback, but the **operator's namespace resolution is the
authoritative gate**. Disabling the webhook (`webhook.enabled=false`)
does not weaken the boundary.

[refgrant]: https://gateway-api.sigs.k8s.io/api-types/referencegrant/

## How resolution works

1. The operator watches `Namespace` objects cluster-wide via the
   controller-runtime cache.
2. On every reconcile of a CR that has a non-nil `namespaceSelector`,
   the operator filters the cached namespace list against the
   selector expression, then drops any matched namespace that does not
   grant tracing from the CR's namespace (own namespace is always
   granted).
3. The result is a sorted `[]string` of namespace names — the
   **allowlist**. Matched-but-ungranted namespaces are reported on the
   CR's `Reconciled` / `CrossNamespaceNotGranted` condition so the
   exclusion is visible.
4. The allowlist is:
   - Written to `.status.targetNamespaces` for debuggability.
   - Pushed into the agent bundle as `target_namespaces` so the agent
     accepts pods from any allowlisted namespace.
5. Any change to a namespace's labels **or grant annotation** triggers a
   re-reconcile of every CR with a non-nil `namespaceSelector`
   (over-enqueue is intentional; the cost is negligible and the
   correctness story is simple).

Three observable cases on `.status.targetNamespaces`:

| Case | Meaning |
|---|---|
| field absent / `null` | The CR has no `namespaceSelector` — evaluation is restricted to the CR's own namespace. |
| empty array `[]` | A selector is set but no namespaces match. No pods will be selected. Common when labels haven't been applied yet. |
| populated array | The allowlist. Pods are selected only in these namespaces. |

## Verifying it on a kind cluster

```bash
# Three namespaces, two labeled tier=prod, one labeled tier=staging
kubectl create ns app-a && kubectl label ns app-a tier=prod
kubectl create ns app-b && kubectl label ns app-b tier=prod
kubectl create ns app-c && kubectl label ns app-c tier=staging

# Each target namespace must consent to being traced from the observer
# namespace. Without this, the allowlist resolves empty.
kubectl annotate ns app-a app-b app-c podtrace.io/allow-tracing-from=observability

# A workload labelled app=api in each
for ns in app-a app-b app-c; do
  cat <<EOF | kubectl -n $ns apply -f -
apiVersion: apps/v1
kind: Deployment
metadata: { name: api, labels: { app: api } }
spec:
  replicas: 1
  selector: { matchLabels: { app: api } }
  template:
    metadata: { labels: { app: api } }
    spec:
      containers:
        - name: curl
          image: curlimages/curl:latest
          command: ["sh","-c","while true; do curl -sS -o /dev/null https://example.com || true; sleep 2; done"]
EOF
done

# ExporterConfig in the observer namespace
kubectl create ns observability
cat <<'EOF' | kubectl -n observability apply -f -
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata: { name: prod-otlp }
spec:
  type: otlp
  otlp: { endpoint: otel:4318, protocol: http, insecure: true }
EOF

# Session that targets every prod namespace
cat <<'EOF' | kubectl -n observability apply -f -
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata: { name: prod-diag }
spec:
  selector: { matchLabels: { app: api } }
  namespaceSelector:
    matchLabels: { tier: prod }
  duration: 30s
  filters: [dns]
  exporterRef: { name: prod-otlp }
EOF

# Wait a few seconds, then inspect the resolved allowlist
sleep 6
kubectl -n observability get podtracesession prod-diag -o jsonpath='{.status.targetNamespaces}{"\n"}'
```

Expected output: `[app-a app-b]` — `app-c` (staging) is excluded.

If you relabel `app-c` to `tier=prod` while the session is still
active, the next reconcile picks it up and the allowlist grows to
`[app-a app-b app-c]`.

```bash
kubectl label ns app-c tier=prod --overwrite
sleep 6
kubectl -n observability get podtracesession prod-diag -o jsonpath='{.status.targetNamespaces}{"\n"}'
```

## Webhook validation

Malformed selectors are caught at admission time:

```yaml
# This is rejected by the validating webhook (if enabled)
namespaceSelector:
  matchExpressions:
    - key: tier
      operator: InvalidOp        # only In/NotIn/Exists/DoesNotExist
      values: [prod]
```

Error: `spec.namespaceSelector: "InvalidOp" is not a valid label selector operator`.

If the webhook is disabled (chart `webhook.enabled=false`), the
controller's defensive path catches the same error during reconcile
and surfaces it as `Degraded=True / NamespaceSelectorInvalid` on the
CR. The session never spawns Jobs.

The webhook also enforces target-namespace consent at admission:

- A `spec.podRefs` entry naming a foreign namespace that has not
  granted access is **rejected**:
  `spec.podRefs: namespace "team-b" does not grant tracing to
  "observability"; the target namespace must carry the annotation
  podtrace.io/allow-tracing-from=...`.
- A `spec.namespaceSelector` that matches ungranted namespaces is
  **admitted with a warning** naming them; the operator excludes them
  from the allowlist.

Because the operator re-checks consent on every reconcile, these are
fast-feedback conveniences, the boundary holds with the webhook off.

## RBAC and namespace permissions

The operator's ClusterRole already grants `namespaces: [get,list,watch]`
cluster-wide (see [operator-rbac.yaml](../deploy/charts/podtrace/templates/operator-rbac.yaml)).
That single grant powers both the allowlist resolution and the
target-namespace consent check — the operator reads the
`podtrace.io/allow-tracing-from` annotation from the same namespace
list. **No new operator RBAC is required by the consent mechanism.**

For continuous `PodTrace`, per-target-namespace RBAC is **not** required
— the agent runs as a DaemonSet under `serviceaccounts/podtrace-agent`,
which has cluster-wide pod-read RBAC. Pod matching happens locally in
each agent's process, against pods running on the same node, gated by
the (grant-filtered) allowlist pushed via the bundle.

For a bounded `PodTraceSession`, the in-Job CLI reads pod metadata via a
per-session ServiceAccount. When a session targets a foreign namespace,
the operator provisions a scoped pod-read `Role`+`RoleBinding` **in that
namespace**, but only after the consent check passes. An ungranted
target never receives this RBAC, so the escape leaves no trace in the
victim namespace.

## Multi-node behaviour

If matched pods land on N nodes, the session controller produces one
Job per node. The Job's `--pod-namespace` and `--pod-name` filters are
seeded from the per-node subset of the match. So a session with
`namespaceSelector: tier=prod` that matches 5 pods spread across 3
nodes produces 3 Jobs, each tracing its local 1-2 pods. See
[crd-podtracesession.md](crd-podtracesession.md#multi-node-behavior)
for details.

## Continuous mode (`PodTrace`)

`PodTrace` accepts the same `namespaceSelector` with identical
semantics. The difference is the agent never finishes — it watches
for matching pods continuously and attaches as they come up. Use this
for production-grade always-on tracing across an environment.

```yaml
apiVersion: podtrace.io/v1alpha1
kind: PodTrace
metadata: { name: prod-live, namespace: observability }
spec:
  selector: { matchLabels: { app: api } }
  namespaceSelector:
    matchLabels: { tier: prod }
  filters: [dns, net]
  exporterRef: { name: prod-otlp }
```

## Common gotchas

- **`namespaceSelector` set, `selector` unset → match nothing**.
  The pod selector still has to do work. `selector` is required.
- **Allowlist empty even though namespaces exist with the right label**.
  Two causes: (1) a race after a label edit — the next reconcile (within
  seconds) picks it up; or (2) the matched namespaces have not granted
  tracing. Check the CR's conditions for `CrossNamespaceNotGranted`, and
  verify the grant: `kubectl get ns team-b -o
  jsonpath='{.metadata.annotations.podtrace\.io/allow-tracing-from}'`.
  If it stays empty, double-check label values:
  `kubectl get ns -l tier=prod`.
- **Same exporter, many CRs**. Each `ExporterConfig` is referenced by
  name in the CR's own namespace only — exporters can't be shared
  cross-namespace by reference. If you want one logical exporter
  across N namespaces, either duplicate the `ExporterConfig` per
  namespace or put the CR in a central observer namespace and target
  outward with `namespaceSelector`.
- **Many target namespaces × many nodes → many Jobs**. For very wide
  rollouts use `TracerConfig.spec.maxConcurrentSessionsPerNode` to
  cap per-node Jobs, or stagger work via `PodTraceSchedule` instead
  of one large session.

## See also

- [crd-podtrace.md](crd-podtrace.md) — continuous-trace CR full spec
- [crd-podtracesession.md](crd-podtracesession.md) — bounded-session CR full spec
- [multi-pod-tracing.md](multi-pod-tracing.md) — CLI mode multi-pod and cross-NS patterns
- [viewing-events.md](viewing-events.md) — where to read the events the trace captured
