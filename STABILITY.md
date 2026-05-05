# Stability and Versioning

This document defines what podtrace promises about its public surface, how
versions move forward, and when fields and behaviors can change.

## Status

Podtrace is pre-1.0. All four CRDs are at `podtrace.io/v1alpha1`:

- `PodTrace` (namespaced, short name `pt`)
- `PodTraceSession` (namespaced, short name `pts`)
- `ExporterConfig` (namespaced, short name `ec`)
- `TracerConfig` (cluster-scoped, short name `tc`)

The CLI and operator are released together from one repository as a single
tagged version (e.g. `v0.11.0`). The Helm chart in
[deploy/charts/podtrace/](deploy/charts/podtrace/) versions independently
(`Chart.yaml.version`) but its `appVersion` always tracks the binary tag.

## What `v1alpha1` means here

We follow [Kubernetes API versioning conventions][k8s-versioning]. For
podtrace specifically:

- **Schemas may change** between minor releases. Field renames, removals,
  and semantic changes are allowed.
- **No conversion webhooks** are provided. You upgrade by editing your
  manifests, not by relying on automatic conversion.
- **Best-effort backward compatibility within a minor release line.** A
  patch release (e.g. `v0.11.0` → `v0.11.1`) will not break existing
  manifests. Minor releases (`v0.11.0` → `v0.12.0`) may.
- **Reserved-but-rejected fields are forward-compatibility markers, not
  promises.** Example: `PodTraceSession.spec.reportRef.objectStore` is
  defined in the schema but rejected by the validating webhook today. It
  will be enabled in a future version; the field name and shape may still
  change before that happens.
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

### Path to `v1beta1`

A CRD graduates from `v1alpha1` to `v1beta1` when **all** of the following
hold for that CRD:

1. Schema has been stable across at least 2 consecutive minor releases.
2. Conversion is documented (manual or webhook-based) for any past
   breaking change.
3. The control plane reconciler for the CRD has end-to-end test coverage
   in the [chainsaw e2e suite](.github/workflows/chainsaw.yml).

A `v1beta1` graduation can land for one CRD without graduating the
others. CRDs at `v1beta1` and `v1alpha1` will be served simultaneously
during transition.

### Path to `v1.0.0`

The repository tags `v1.0.0` when:

1. All four CRDs are at `v1beta1` or `v1` and have been stable for ≥6
   months.
2. CLI flag surface has been stable for ≥6 months.
3. Helm chart values have been stable for ≥6 months.
4. A formal API deprecation policy is in place.

Until then, expect `v0.x` cadence with the rules above.

## Related documents

- [CHANGELOG.md](CHANGELOG.md) — release-by-release record, including
  every breaking change.
- [doc/compatibility.md](doc/compatibility.md) — kernel, Kubernetes,
  architecture, and distro support matrix.
- [doc/migration.md](doc/migration.md) — how to move between the CLI and
  CRD models. Not the same as schema migration.
- [doc/crd-podtrace.md](doc/crd-podtrace.md),
  [doc/crd-podtracesession.md](doc/crd-podtracesession.md),
  [doc/crd-exporterconfig.md](doc/crd-exporterconfig.md),
  [doc/crd-tracerconfig.md](doc/crd-tracerconfig.md) — per-CRD field
  reference.