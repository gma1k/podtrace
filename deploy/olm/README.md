# OLM bundle source

Hand-authored sources for podtrace's [Operator Lifecycle Manager (OLM)](https://olm.operatorframework.io/)
bundle published to [OperatorHub.io](https://operatorhub.io/) via the
[community-operators](https://github.com/k8s-operatorhub/community-operators)
catalog.

## Files

| File | Purpose |
|------|---------|
| `csv-template.yaml` | ClusterServiceVersion template with `__VERSION__`, `__PREVIOUS_VERSION__`, `__CREATED_AT__`, `__SKIP_RANGE_UPPER__` placeholders. The single hand-authored file describing the operator to OLM. |
| `annotations.yaml` | Bundle metadata (channel, package, mediatype). Stable across releases. |
| `bundle.Dockerfile.template` | Bundle image Dockerfile. Stable across releases; `__VERSION__` is substituted at build time for labels only. |

## Build flow

```
helm template (chart) ─┐
                       ├─► scripts/build-olm-bundle.sh ─► bundle/<version>/
csv-template.yaml ─────┤                                    manifests/
                       │                                      *.crd.yaml
annotations.yaml ──────┤                                      podtrace.csv.yaml
                       │                                    metadata/
bundle.Dockerfile.tpl ─┘                                      annotations.yaml
                                                            bundle.Dockerfile
```

The Helm chart (`deploy/charts/podtrace/`) is the **single source of
truth** for the operator's runtime manifests (Deployment, RBAC, CRDs).
The CSV template references those manifests by structure; the build
script renders them via `helm template` and folds them into the CSV.

This avoids the divergence-bug factory of maintaining a parallel
`config/` directory, while still producing an OperatorHub-compliant
bundle. Pattern modelled on cert-manager, jaeger-operator, and
tempo-operator.

## Output (gitignored)

`bundle/<version>/` is generated per-release. Contents are copied into
the contributor's fork of `k8s-operatorhub/community-operators` under
`operators/podtrace/<version>/` for submission.

## Validation

After build:

```bash
operator-sdk bundle validate ./bundle/<version> --select-optional name=community
```

This runs the same checks community-operators CI runs.

## Local end-to-end on kind

```bash
make bundle-build bundle-push VERSION=v0.11.7
operator-sdk olm install
operator-sdk run bundle ghcr.io/gma1k/podtrace-bundle:v0.11.7 \
  --install-mode AllNamespaces --namespace podtrace-system
```
