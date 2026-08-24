# API Versioning and CRD Graduation

How podtrace's CRD versions move forward, what changes are allowed at each
stage, and the procedure for graduating a CRD from one version to the next.

This is about **schema** migration. For moving from the CLI binary to the
CR-driven model, see [migration.md](migration.md), a different thing that
happens to share the word. For what each version promises, see
[STABILITY.md](../STABILITY.md).

## The graduation contract

**Graduation introduces no schema change.**

A CRD graduates `v1alpha1` to `v1beta1` as an identical schema. The new
version is a copy: same fields, same types, same validation. Storage moves
to the new version, existing objects are migrated, and the old version is
retired.

API changes happen **before** graduation or **after** it. They never happen
at the version boundary.

The consequence is that podtrace serves multiple versions with
`conversion.strategy: None` and needs no conversion webhook, not because
webhooks were judged too expensive, but because there is nothing to convert.

### Why the boundary is the wrong place to change shape

Kubernetes offers two conversion strategies for CRDs: `None`, where the API
server relabels `apiVersion` and prunes the object against the requested
version's schema, and `Webhook`, where it calls an endpoint you run.
Declarative in-process conversion was proposed as
[KEP-3945](https://github.com/kubernetes/enhancements/issues/3945) and
closed as not planned, so there is no third option.

Under `strategy: None`, reads are safe: a client asking for a version that
lacks a field simply does not see it. **Writes are not.** If the served
versions differ in shape, a write through the older version discards
whatever that version's schema does not describe:

| Write path through the older version | Field only in the storage version |
|---|---|
| `kubectl apply` (client-side) | lost |
| read-modify-write via a typed client | lost |
| `kubectl apply --server-side`, non-owning field manager | preserved |
| `kubectl apply --server-side --force-conflicts` | lost |

Two of those are what GitOps controllers do on a normal sync. So an
"additive-only" superset is not sufficient to make `strategy: None` safe,
it makes reads safe and leaves writes lossy.

If the schemas are **identical**, the failure mode cannot occur, and
Kubernetes deprecation policy rule, "API objects must be able to
round-trip between API versions in a given release without information
loss", holds by construction rather than by promise.

`strategy: Webhook` was considered and rejected separately. A conversion
webhook sits in the **read** path of the CRs, including the operator's own
reconcile reads. When it is unavailable, existing traces stop reconciling.
For a diagnostic tool, being unavailable during an incident is the specific
failure this project cannot accept.

## Where API change is allowed

Podtrace follows the [Kubernetes deprecation
policy](https://kubernetes.io/docs/reference/using-api/deprecation-policy/)
rather than defining its own. The three rules that matter here:

- **Rule #1** — once an element exists at a version, it can never be removed
  from that version, nor have its behavior significantly changed.
- **Rule #2** — objects must round-trip between served versions without
  information loss.
- **Rule #4a** — alpha versions may be removed in any release with no prior
  deprecation notice. Beta versions must be served for 9 months or 3 minor
  releases after deprecation, whichever is longer.

Applied to podtrace:

| Stage | What is allowed |
|---|---|
| While at `v1alpha1` | Rename, retype, restructure, remove. No notice owed. Record it in [CHANGELOG.md](../CHANGELOG.md) with a `BREAKING CHANGE` footer and in the history below. |
| At graduation | Nothing. The schema is copied unchanged. |
| At `v1beta1` and later | Add optional fields. Deprecate fields, but never remove them from that version. |

Rule #1 is the reason graduation is a deadline and not a milestone: every
awkward field that reaches `v1beta1` is carried until `v1`. A rename after
graduation means adding the new field and keeping the old one indefinitely.

**So the cleanup window is now, while the CRDs are at `v1alpha1`.** If a
field name or shape is wrong, that is the time to say so.

## The cutover procedure

A single-step swap is not possible. The API server pins a version in
`spec.versions` for as long as it appears in `status.storedVersions`:

```
status.storedVersions[0]: Invalid value: "v1alpha1": missing from
spec.versions; v1alpha1 was previously a storage version, and must remain in
spec.versions until a storage migration ensures no data remains persisted in
v1alpha1 and removes v1alpha1 from status.storedVersions
```

So there is always an overlap window. Graduation spans two releases.

### Release N — add the new version and migrate storage

1. **Add `v1beta1` with an identical schema.** A new `api/v1beta1` package
   carrying the same types, with `+kubebuilder:storageversion` moved to it.
   Both versions `served: true`; `storage: true` on `v1beta1` only.
2. **Migrate storage.** Write every existing object once so it re-persists
   in the new version. Any no-op write does it — the operation must be
   idempotent and safe to re-run.
3. **Patch `status.storedVersions`** to list only the new version, which
   unpins the old one.

At this point both versions are served, the schemas are identical, and no
client can lose data whichever version it writes through.

### Release N+1 — retire the old version

4. **Remove `v1alpha1` from `spec.versions`.** Existing objects are
   untouched; clients pinned to the old version get a `NotFound` for the
   resource and must update `apiVersion`.

For adopters, migration is editing one line. That is the whole of it,
because the schemas were identical.

### During the overlap

Both versions work for reads and writes. Prefer the newer version in
manifests so there is nothing to change at step 4.

## Enforcement

Stating the contract is not enough to hold it — the previous version of this
policy was a disclaimer with nothing behind it.

- `make manifests` regenerates the CRDs, and the `manifests-drift` CI job
  fails on stale output.
- A CI check fails any PR whose generated CRD diff removes or renames a
  field unless the commit carries a `BREAKING CHANGE` footer. This is what
  keeps the history below complete.
- Once a CRD serves two versions, a schema-identity check asserts that the
  served versions are the same shape, and a chainsaw scenario proves it
  against a live API server in both the read and the write direction.

## Breaking change history

Every schema or behavioral break, and what an adopter had to do. Graduation
gate 2 in [STABILITY.md](../STABILITY.md) depends on this list being
complete.

| Release | CRD | Change | What adopters had to do |
|---|---|---|---|
| v0.11.10 | PodTraceSession | `.status.phase` renamed to `.status.state`; the `SessionPhase` values became `SessionState` with the same names | Update anything reading `.status.phase` — `kubectl` output columns, scripts, dashboards. No manifest change: the field is status-only. |
| v0.13.10 | PodTrace, PodTraceSession, PodTraceSchedule | Cross-namespace targeting requires the target namespace to opt in with the `podtrace.io/allow-tracing-from` annotation | Annotate target namespaces. Without it, existing cross-namespace CRs silently narrow to their own namespace. See [cross-namespace-cr-targeting.md](cross-namespace-cr-targeting.md). |

Two things about this list are worth stating plainly rather than leaving to
be discovered.

The `v0.11.10` rename shipped in a **patch** release, which the pre-1.0 rules
in [STABILITY.md](../STABILITY.md) say will not break existing CRDs, and it
was not recorded under a `BREAKING` heading at the time. The rule was right
and the release did not follow it. The CI check described under
[Enforcement](#enforcement) exists because a policy that depends on
remembering is not a policy.

Neither change would have been solved by a conversion webhook. The first is a
status field, written by the operator and never round-tripped from a
manifest; the second is behavioral, and conversion only addresses shape. The
argument for skipping conversion does not rest on this list being short — it
rests on the graduation contract above.

## Related documents

- [STABILITY.md](../STABILITY.md) — what each version promises, and the
  graduation gates
- [ROADMAP.md](../ROADMAP.md) — which CRDs are being worked toward
  graduation
- [CHANGELOG.md](../CHANGELOG.md) — release-by-release record
- [migration.md](migration.md) — CLI binary to CR-driven workflows
