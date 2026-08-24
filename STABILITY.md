# Stability and Versioning

This document defines what podtrace promises about its public surface, how
versions move forward, and when fields and behaviors can change.

## Status

Podtrace is pre-1.0. All six CRDs are at `podtrace.io/v1alpha1`:

- `PodTrace` (namespaced, short name `pt`)
- `PodTraceSession` (namespaced, short name `pts`)
- `PodTraceSchedule` (namespaced, short name `ptsch`)
- `ExporterConfig` (namespaced, short name `ec`)
- `TracerConfig` (cluster-scoped, short name `tc`)
- `ApplicationTrace` (namespaced, short name `appt`)

The CLI and operator are released together from one repository as a single
tagged version (e.g. `v0.11.0`). The Helm chart in
[deploy/charts/podtrace/](deploy/charts/podtrace/) versions independently
(`Chart.yaml.version`) but its `appVersion` always tracks the binary tag.

## What `v1alpha1` means here

We follow [Kubernetes API versioning conventions][k8s-versioning]. For
podtrace specifically:

- **Schemas may change** between minor releases. Field renames, removals,
  and semantic changes are allowed.
- **No conversion webhooks**, by design rather than by omission. Versions
  are graduated as identical schemas, so `conversion.strategy: None` is
  correct and there is nothing for a webhook to convert. Shape changes
  happen while a CRD is at `v1alpha1`, never at a version boundary. The
  contract and the cutover procedure are in
  [docs/api-versioning.md](docs/api-versioning.md).
- **Best-effort backward compatibility within a minor release line.** A
  patch release (e.g. `v0.11.0` → `v0.11.1`) will not break existing
  manifests. Minor releases (`v0.11.0` → `v0.12.0`) may.
- **Reserved fields are forward-compatibility markers, not promises.** A
  field may appear in the schema before its behavior is fully implemented.
  Until it is, the validating webhook may reject it, the operator may
  ignore it, and its name and shape may still change. Such fields are
  called out as reserved in the reference docs for the resource that
  defines them.
- **Production use is allowed but not recommended without pinning.** Pin
  to a specific `v0.x.y` tag and read this changelog before each upgrade.

[k8s-versioning]: https://kubernetes.io/docs/reference/using-api/#api-versioning

## Versioning policy

Three artifacts version on three different cadences:

| Artifact | Versioning | Where | Cadence |
|---|---|---|---|
| Operator + agent + CLI binary | Semver, single tag | Git tag `vX.Y.Z` | Coupled — one tag, one binary |
| Container image | Mirrors binary tag | `ghcr.io/gma1k/podtrace:vX.Y.Z` (when published) | Same as binary |
| Helm chart | Semver, independent | `Chart.yaml.version` | Bumps per chart change; `appVersion` always tracks the binary |
| CRDs (`podtrace.io/vN`) | Kubernetes API conventions | Bumped only on breaking schema change | Independent of binary version |

### Pre-1.0 (`v0.x.y`) — current

While we are at `v0.x`:

- Minor versions (`v0.X.0`) may include breaking CRD schema changes. We
  document them in [CHANGELOG.md](CHANGELOG.md) under a `### Breaking`
  heading and call them out in release notes.
- Patch versions (`v0.X.Y`) will not break existing CRDs. Bug fixes,
  internal refactors, and additive non-required fields are allowed.
- The CLI flag surface has the same rule: minors may change, patches will
  not.
- Helm chart values: same rule. Minors may rename or restructure values;
  patches will not.

### How releases get versioned (pre-1.0)

While Podtrace at `v0.x`, release-please bumps **patch** for both
`feat:` and `fix:` (and `refactor:`/`perf:`). The minor digit only
moves when a commit explicitly carries a `BREAKING CHANGE:` footer (or
when a maintainer overrides the next version via release-please's
`Release-As: 0.X.0` footer). This makes the minor bump a deliberate
opt-in rather than a side effect of every new feature.

After `v1.0.0`, the standard semver rules apply: `feat:` bumps minor,
`BREAKING CHANGE:` bumps major.

### Path to `v1beta1`

A CRD graduates from `v1alpha1` to `v1beta1` when **all** of the following
hold for that CRD:

1. The CRD's generated schema has not changed in the last 3 releases.
   Verifiable from the committed CRD manifests, not from judgement.
2. Every past breaking change for that CRD is recorded in the history
   table in [docs/api-versioning.md](docs/api-versioning.md), with what
   an adopter had to do.
3. The control plane reconciler for the CRD has end-to-end test coverage
   in the [chainsaw e2e suite](.github/workflows/chainsaw.yml).

A `v1beta1` graduation can land for one CRD without graduating the
others.

Graduation copies the schema unchanged — a `v1beta1` that differs from its
`v1alpha1` is not a graduation, it is a breaking change wearing a new
label. Both versions are served during the transition, which spans two
releases while stored objects are migrated, and the older version is then
removed. The procedure and the reasoning are in
[docs/api-versioning.md](docs/api-versioning.md).

### Path to `v1.0.0`

The repository tags `v1.0.0` when:

1. All six CRDs are at `v1beta1` or `v1` and have been stable for ≥6
   months.
2. CLI flag surface has been stable for ≥6 months.
3. Helm chart values have been stable for ≥6 months.
4. A formal API deprecation policy is in place. Satisfied by
   [docs/api-versioning.md](docs/api-versioning.md), which adopts the
   upstream [Kubernetes deprecation
   policy](https://kubernetes.io/docs/reference/using-api/deprecation-policy/)
   rather than defining a competing scheme.

Until then, expect `v0.x` cadence with the rules above.

## Related documents

- [CHANGELOG.md](CHANGELOG.md) — release-by-release record, including
  every breaking change.
- [docs/compatibility.md](docs/compatibility.md) — kernel, Kubernetes,
  architecture, and distro support matrix.
- [docs/api-versioning.md](docs/api-versioning.md) — the graduation
  contract, the deprecation policy, the version cutover procedure, and the
  breaking-change history.
- [docs/migration.md](docs/migration.md) — how to move between the CLI and
  CRD models. Not the same as schema migration.
- [docs/crd-podtrace.md](docs/crd-podtrace.md),
  [docs/crd-podtracesession.md](docs/crd-podtracesession.md),
  [docs/crd-podtraceschedule.md](docs/crd-podtraceschedule.md),
  [docs/crd-exporterconfig.md](docs/crd-exporterconfig.md),
  [docs/crd-tracerconfig.md](docs/crd-tracerconfig.md),
  [docs/crd-applicationtrace.md](docs/crd-applicationtrace.md) — per-CRD
  field reference.
