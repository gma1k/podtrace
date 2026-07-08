# Podtrace

eBPF-driven diagnostic tool for Kubernetes applications.

This chart installs the **podtrace operator** and its
CustomResourceDefinitions. The operator reconciles `PodTrace`,
`PodTraceSession`, `PodTraceSchedule`, `ExporterConfig`, and
`TracerConfig` resources, and rolls out the `podtrace-agent` DaemonSet
on demand when a `TracerConfig` is created.

For project background, architecture, and CLI usage, see the
[main project README](https://github.com/gma1k/podtrace#readme) and the
[docs/](https://github.com/gma1k/podtrace/tree/main/docs) directory.

## TL;DR

```bash
helm install podtrace \
  oci://ghcr.io/gma1k/charts/podtrace \
  --version <chart-version> \
  --namespace podtrace-system \
  --create-namespace
```

## Prerequisites

- **Kubernetes** 1.28 or newer.
- **Linux nodes with kernel 5.8+** (BPF ring buffer).
- For full path resolution and the gRPC / FastCGI probes:
  `/sys/kernel/btf/vmlinux` must be present on each node (BTF support —
  available on most modern distros).
- **cert-manager** is required only if you enable the validating
  webhook (`webhook.enabled=true`, default `false`).

See [docs/compatibility.md](https://github.com/gma1k/podtrace/blob/main/docs/compatibility.md)
for the supported kernel / distro / Kubernetes matrix.

## Installing

### OCI (recommended)

```bash
helm install podtrace \
  oci://ghcr.io/gma1k/charts/podtrace \
  --version <chart-version> \
  --namespace podtrace-system \
  --create-namespace
```

### Verifying the chart signature

Each chart version is signed with cosign keyless OIDC:

```bash
cosign verify oci://ghcr.io/gma1k/charts/podtrace:<chart-version> \
  --certificate-identity-regexp "^https://github.com/gma1k/podtrace" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

## Uninstalling

```bash
helm uninstall podtrace --namespace podtrace-system
```

CRDs are retained by default (`crds.keep=true`) so that user-created
`PodTrace`, `PodTraceSession`, and `PodTraceSchedule` resources are not
cascade-deleted. Remove them explicitly when you are sure:

```bash
kubectl delete crd \
  tracerconfigs.podtrace.io \
  exporterconfigs.podtrace.io \
  podtraces.podtrace.io \
  podtracesessions.podtrace.io \
  podtraceschedules.podtrace.io
```

## Configuration

The configuration surface is organized top-down in
[`values.yaml`](values.yaml). Each section is documented inline with
defaults and edge cases.

| Section | Purpose |
| --- | --- |
| `crds` | CustomResourceDefinition installation, adoption, and retention |
| `image` | Shared container image used by operator, agent, and session Jobs |
| `namespace` | `podtrace-system` namespace management |
| `operator` | Controller-runtime Deployment running the reconcilers |
| `agent` | Per-node tracer DaemonSet — rolled out on demand by `TracerConfig` |
| `session` | Job template used for `PodTraceSession` forensic runs |
| `webhook` | Validating webhook for the CRDs (requires cert-manager) |
| `rbac` | Optional overrides for cluster and namespaced RBAC |
| `metrics` | Prometheus `ServiceMonitor` / `PodMonitor` integration |
| `examples` | Optional sample `TracerConfig` / `ExporterConfig` resources |

Read the full default values:

```bash
helm show values oci://ghcr.io/gma1k/charts/podtrace --version <chart-version>
```

## Upgrading

Use `helm upgrade --install`. Chart `version` and binary `appVersion`
are decoupled — the chart version bumps for any chart change, while
`appVersion` tracks the podtrace binary release the chart targets.

Always read the [CHANGELOG](https://github.com/gma1k/podtrace/blob/main/CHANGELOG.md)
before upgrading across a minor version.

## Stability

The CRDs are at `v1alpha1`; field names may change before promotion to
`v1beta1`. See [STABILITY.md](https://github.com/gma1k/podtrace/blob/main/STABILITY.md)
for the project's stability statement.

## Links

- [Source code](https://github.com/gma1k/podtrace)
- [Documentation](https://github.com/gma1k/podtrace/tree/main/docs)
- [CRD reference](https://github.com/gma1k/podtrace/tree/main/docs)
- [Issue tracker](https://github.com/gma1k/podtrace/issues)
- [Security policy](https://github.com/gma1k/podtrace/blob/main/SECURITY.md)