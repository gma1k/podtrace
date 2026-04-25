# ExporterConfig — exporter destination CR

`ExporterConfig` is namespace-scoped and reusable. Multiple `PodTrace`
or `PodTraceSession` CRs in the same namespace can reference one
`ExporterConfig` via `spec.exporterRef.name`. The operator materializes
each ExporterConfig referenced into an exporter bundle (ConfigMap +
optional Secret) in `podtrace-system`, which agents and session Jobs
read.

## Five exporter types

The CRD's `spec.type` is an enum: `otlp` | `jaeger` | `zipkin` |
`splunk` | `datadog`. The CRD also requires the matching typed field
to be populated; the validating webhook enforces this cross-field
invariant.

### OTLP

```yaml
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata:
  name: otlp-collector
  namespace: my-app
spec:
  type: otlp
  otlp:
    endpoint: otel-collector.observability:4318
    protocol: http              # http | grpc
    insecure: true              # disable TLS — do not use in prod
    headers:
      - name: X-Tenant
        value: team-a            # literal header
      - name: Authorization
        valueFrom:
          name: otlp-auth         # Secret in same namespace
          key: bearer-token
```

Literal-valued headers go straight into the bundle ConfigMap.
Secret-valued headers are loaded into the companion Secret under the
fixed `credential` key. Today only ONE Secret-valued header is
supported per OTLP exporter.

### Jaeger

```yaml
spec:
  type: jaeger
  jaeger:
    endpoint: http://jaeger-collector.observability:14268/api/traces
```

No credentials. Bundle is ConfigMap-only.

### Zipkin

```yaml
spec:
  type: zipkin
  zipkin:
    endpoint: http://zipkin.observability:9411/api/v2/spans
```

No credentials. Bundle is ConfigMap-only.

### Splunk HEC

```yaml
spec:
  type: splunk
  splunk:
    endpoint: https://splunk.example.com:8088/services/collector
    tokenSecretRef:
      name: splunk-hec-token
      key: token
```

The bundle's companion Secret carries the resolved HEC token under the
`credential` key.

### DataDog

```yaml
spec:
  type: datadog
  datadog:
    site: datadoghq.com           # or datadoghq.eu, etc.
    apiKeySecretRef:
      name: dd-api-key
      key: api_key
```

The companion Secret carries the resolved API key under `credential`.

## Optional fields shared by all types

```yaml
spec:
  samplePercent: 50               # 0-100; sampler applied at the exporter SDK
```

## Spec reference (full)

| Field | Type | Notes |
|---|---|---|
| `type` | enum | `otlp` / `jaeger` / `zipkin` / `splunk` / `datadog` |
| `otlp.endpoint` | string | Required when `type=otlp`. |
| `otlp.protocol` | enum | `http` / `grpc`. Defaults to `http`. |
| `otlp.insecure` | bool | Disables TLS. |
| `otlp.headers[]` | list | Either literal `value` or `valueFrom: SecretKeySelector`. |
| `otlp.headersFromSecret` | object | Reserved for "every Secret key becomes a header". |
| `jaeger.endpoint` | string | Required when `type=jaeger`. |
| `zipkin.endpoint` | string | Required when `type=zipkin`. |
| `splunk.endpoint` | string | Splunk HEC URL. |
| `splunk.tokenSecretRef` | object | `{name, key}` selector. |
| `datadog.site` | string | E.g. `datadoghq.com`, `datadoghq.eu`. |
| `datadog.apiKeySecretRef` | object | `{name, key}` selector. |
| `samplePercent` | int 0-100 | Optional sampling rate. |

## Bundle materialization

For each PodTrace or session referencing an ExporterConfig, the
operator creates two objects in `podtrace-system`:

1. **ConfigMap** named `pt-bundle-<exporterUID>` (continuous) or
   `pts-bundle-<sessionUID>` (session). Carries
   `type`, `endpoint`, `protocol`, `insecure`, `site`,
   `headers.<name>` for literals, `header_secret_name` when applicable,
   `sample_percent`, and a `bundle.yaml` blob the CLI consumes.
2. **Secret** with the same name (created only when the exporter
   references credential material). Carries the resolved value under
   the fixed `credential` key.

## Credential rotation

When you update the upstream Secret referenced by an ExporterConfig,
the operator re-reads it on the next reconcile and patches the
companion bundle Secret in `podtrace-system`. Agents pick up the new
credential on their next bundle reload (driven by ConfigMap
ResourceVersion change).

To force an immediate refresh without waiting for the next reconcile
tick:

```bash
kubectl annotate exporterconfig <name> -n <ns> \
  podtrace.io/rotated-at="$(date -Iseconds)" --overwrite
```

This causes the operator to see a generation bump and re-render the
bundle.

## Cross-namespace references

ExporterConfig and the user-namespace Secret it references must live
in the same namespace. The operator does not (and intentionally cannot)
read Secrets from other user namespaces — that boundary keeps the
operator's RBAC narrow.

If you want to share one ExporterConfig across many namespaces, copy
the CR into each namespace (the bundle is per-CR anyway).

## Status reference

```yaml
status:
  conditions:
    - type: Reconciled
      status: "True"
      reason: Reconciled
```

ExporterConfig itself is mostly passive — the heavy reconcile happens
when a PodTrace or PodTraceSession references it.

## Related

- [crd-podtrace.md](crd-podtrace.md)
- [crd-podtracesession.md](crd-podtracesession.md)
- [operator.md](operator.md)
- [tracing-exporters.md](tracing-exporters.md) — original CLI-mode exporter docs
