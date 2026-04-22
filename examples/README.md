# Podtrace operator examples

Happy-path manifests aligned with the `podtrace.io/v1alpha1` CRD schema.
Apply them in order:

```sh
# Install the chart (CRDs + namespace) first:
helm install podtrace ./deploy/charts/podtrace

# Cluster-wide infrastructure config:
kubectl apply -f examples/tracerconfig.yaml

# Namespaced exporter, referenced by traces:
kubectl apply -f examples/exporterconfig-otlp.yaml

# Continuous realtime trace:
kubectl apply -f examples/podtrace.yaml

# Or a bounded diagnose-mode trace:
kubectl apply -f examples/podtracesession.yaml
```

| File | Purpose |
|---|---|
| [tracerconfig.yaml](tracerconfig.yaml) | Cluster-scoped `TracerConfig` — agent image, resources, BTF mode. One per cluster. |
| [exporterconfig-otlp.yaml](exporterconfig-otlp.yaml) | Reusable OTLP exporter with Secret-backed headers. |
| [exporterconfig-datadog.yaml](exporterconfig-datadog.yaml) | DataDog exporter with a Secret-backed API key. |
| [podtrace.yaml](podtrace.yaml) | Continuous tracing of pods matching `app=api`. |
| [podtracesession.yaml](podtracesession.yaml) | Bounded 5-minute diagnose of the same selector. |
