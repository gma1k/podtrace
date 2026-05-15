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
| [podtraceschedule.yaml](podtraceschedule.yaml) | Recurring diagnose — fires a new `PodTraceSession` every 10 minutes using a session template. |
| [diagnose-demo.yaml](diagnose-demo.yaml) | Self-contained end-to-end demo: a curl workload plus a 30s session with a `reportRef` ConfigMap sink. One `kubectl apply -f` away from a populated `.status.summary`. |

## Quick end-to-end on kind

Once the chart is installed and a `default` TracerConfig exists pointing at your loaded image:

```sh
kubectl apply -f examples/diagnose-demo.yaml
kubectl -n podtrace-demo rollout status deploy/chatty --timeout=60s
kubectl -n podtrace-demo get podtracesession diag-demo -w      # wait for Completed
kubectl -n podtrace-demo get podtracesession diag-demo \
  -o jsonpath='{.status.summary}{"\n"}'                        # event counts
kubectl -n podtrace-demo get cm diag-demo-report \
  -o jsonpath='{.data.report\.txt}'                            # full report
```
