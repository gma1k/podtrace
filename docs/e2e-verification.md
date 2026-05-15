# End-to-end verification playbook

Manual CLI playbook to exercise every operator feature in order against
a real cluster (kind / minikube / any). Each section is independent —
run from the top to verify a fresh install, or pick the one that
covers the feature you just touched.

The companion chainsaw suite under [test/chainsaw/tests](../test/chainsaw/tests)
runs the same checks unattended. This document is the
copy-paste-while-watching counterpart.

## Prerequisites

- A Kubernetes cluster reachable via `KUBECONFIG`
- The podtrace operator + agent installed in `podtrace-system`
- `kubectl podtrace` binary on `$PATH`, or a local build at
  `/tmp/podtrace`:

  ```bash
  go build -o /tmp/podtrace ./cmd/podtrace
  alias kpt=/tmp/podtrace
  ```

- A clean test namespace:

  ```bash
  kubectl create namespace e2e
  ```

## 0 — Cluster health snapshot

```bash
echo "=== operator ==="
kubectl -n podtrace-system get pods -l app.kubernetes.io/component=operator
echo "=== agent (one per node) ==="
kubectl -n podtrace-system get pods -l podtrace.io/component=agent -o wide
echo "=== CRDs ==="
kubectl get crd | grep podtrace.io
echo "=== operator log scan (errors only, last 30m) ==="
kubectl -n podtrace-system logs deploy/podtrace-operator --since=30m \
  | grep -iE '"level":"error"|panic|stacktrace' | head -5
```

Expect: operator + N agents Running, 5 CRDs, no error-level log lines.

## Agent failure surfaces on the parent CR

Goal: an agent-side build error becomes a `Degraded` condition on the
parent CR, not a buried log line.

```bash
cat <<'EOF' | kubectl -n e2e apply -f -
apiVersion: podtrace.io/v1alpha1
kind: PodTrace
metadata: { name: missing-exporter }
spec:
  selector: { matchLabels: { app: foo } }
  exporterRef: { name: does-not-exist }
EOF
sleep 8
kubectl -n e2e get podtraces.podtrace.io missing-exporter \
  -o jsonpath='{range .status.conditions[*]}{.type}={.status}/{.reason}: {.message}{"\n"}{end}'
```

Expect `Degraded=True/ExporterNotFound: ExporterConfig e2e/does-not-exist not found`,
`Ready=False/ExporterNotFound`. Clean up:

```bash
kubectl -n e2e delete podtraces.podtrace.io missing-exporter
```

## Non-OTLP exporters (jaeger / zipkin / splunk / datadog)

Goal: all five `ExporterConfig` types are accepted and their bundles
materialize. Continuous-mode coverage of zipkin uses the OTel
Collector fallback (see [tracing-exporters.md](tracing-exporters.md)).

```bash
cat <<'EOF' | kubectl -n e2e apply -f -
apiVersion: v1
kind: Secret
metadata: { name: dd-creds }
stringData: { api_key: dummy-dd-key }
---
apiVersion: v1
kind: Secret
metadata: { name: splunk-creds }
stringData: { token: dummy-splunk-token }
---
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata: { name: ec-otlp }
spec:
  type: otlp
  otlp: { endpoint: otel:4318, protocol: http, insecure: true }
---
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata: { name: ec-jaeger }
spec:
  type: jaeger
  jaeger: { endpoint: jaeger:4318 }
---
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata: { name: ec-zipkin }
spec:
  type: zipkin
  zipkin: { endpoint: "http://zipkin:9411/api/v2/spans" }
---
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata: { name: ec-datadog }
spec:
  type: datadog
  datadog:
    site: datadoghq.eu
    apiKeySecretRef: { name: dd-creds, key: api_key }
---
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata: { name: ec-splunk }
spec:
  type: splunk
  splunk:
    endpoint: "https://splunk-hec:8088"
    tokenSecretRef: { name: splunk-creds, key: token }
EOF

sleep 4
kubectl -n e2e get exporterconfigs
```

Expect all 5 with `READY=true`.

Now run a session via the jaeger exporter to confirm the non-OTLP
wiring drives a Job end-to-end:

```bash
cat <<'EOF' | kubectl -n e2e apply -f -
apiVersion: apps/v1
kind: Deployment
metadata: { name: web, labels: { app: web } }
spec:
  replicas: 1
  selector: { matchLabels: { app: web } }
  template:
    metadata: { labels: { app: web } }
    spec:
      containers:
        - name: curl
          image: curlimages/curl:latest
          command: ["sh","-c","while true; do curl -sS -o /dev/null https://example.com || true; sleep 2; done"]
---
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata: { name: nonotlp-jaeger }
spec:
  selector: { matchLabels: { app: web } }
  duration: 15s
  filters: [dns, net]
  exporterRef: { name: ec-jaeger }
  reportRef:
    configMap: { name: nonotlp-report }
EOF

kubectl -n e2e wait deploy/web --for=condition=Available --timeout=60s

until [ "$(kubectl -n e2e get podtracesession nonotlp-jaeger -o jsonpath='{.status.state}')" = "Completed" ]; do sleep 3; done
kubectl -n e2e get podtracesession nonotlp-jaeger
kubectl -n e2e get cm nonotlp-report -o jsonpath='{.data.report\.txt}' | head -20

kubectl -n e2e delete podtracesession nonotlp-jaeger
```

Expect `STATE=Completed`, ReportRef ConfigMap populated.

## Cross-namespace NamespaceSelector

Goal: `namespaceSelector` resolves to the correct allowlist, written
on `.status.targetNamespaces`. Full background:
[cross-namespace-cr-targeting.md](cross-namespace-cr-targeting.md).

```bash
kubectl create ns e2e-prod-a && kubectl label ns e2e-prod-a tier=prod
kubectl create ns e2e-prod-b && kubectl label ns e2e-prod-b tier=prod
kubectl create ns e2e-staging  && kubectl label ns e2e-staging tier=staging

cat <<'EOF' | kubectl -n e2e apply -f -
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata: { name: ns-selector-test }
spec:
  selector: { matchLabels: { app: web } }
  namespaceSelector: { matchLabels: { tier: prod } }
  duration: 15s
  filters: [dns]
  exporterRef: { name: ec-otlp }
EOF

sleep 6
kubectl -n e2e get podtracesession ns-selector-test \
  -o jsonpath='{.status.targetNamespaces}{"\n"}'
```

Expect: `[e2e-prod-a e2e-prod-b]` — `e2e-staging` excluded.

Clean up:

```bash
kubectl -n e2e delete podtracesession ns-selector-test --ignore-not-found
kubectl delete ns e2e-prod-a e2e-prod-b e2e-staging --wait=false
```

## ObjectStore reports

Goal: malformed URI rejected to `STATE=Failed`; valid URI wires the
upload sidecar. Full guide:
[object-store-reports.md](object-store-reports.md).

```bash
# Malformed URI
cat <<'EOF' | kubectl -n e2e apply -f -
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata: { name: bad-uri }
spec:
  selector: { matchLabels: { app: web } }
  duration: 30s
  exporterRef: { name: ec-otlp }
  reportRef:
    objectStore: { uri: "ftp://example.com/bucket" }
EOF
sleep 4
kubectl -n e2e get podtracesession bad-uri
kubectl -n e2e get podtracesession bad-uri \
  -o jsonpath='{.status.conditions[?(@.type=="Degraded")].message}{"\n"}'

kubectl -n e2e delete podtracesession bad-uri
```

Expect `STATE=Failed`, message includes `unsupported URI scheme "ftp"`.

Now the sidecar wiring (requires `TracerConfig.spec.session.sidecarUploader=true`):

```bash
# Ensure sidecar uploader is enabled
kubectl get tc default -o jsonpath='{.spec.session.sidecarUploader}'
# If false:
# kubectl patch tc default --type=merge -p '{"spec":{"session":{"sidecarUploader":true}}}'

cat <<'EOF' | kubectl -n e2e apply -f -
apiVersion: v1
kind: Secret
metadata: { name: s3-creds }
stringData:
  access_key_id: dummy
  secret_access_key: dummy
  region: us-east-1
---
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata: { name: s3-sidecar }
spec:
  selector: { matchLabels: { app: web } }
  duration: 15s
  exporterRef: { name: ec-otlp }
  reportRef:
    objectStore:
      uri: "s3://my-bucket/reports/"
      credentialsSecretRef: { name: s3-creds }
EOF

sleep 8

JOB=$(kubectl -n podtrace-system get jobs -l podtrace.io/session=s3-sidecar -o name | head -1)
echo "initContainers:"
kubectl -n podtrace-system get "$JOB" -o jsonpath='{range .spec.template.spec.initContainers[*]}{.name}{"\n"}{end}'
echo "credential volume:"
kubectl -n podtrace-system get "$JOB" -o jsonpath='{range .spec.template.spec.volumes[*]}{.name}{"\n"}{end}' | grep -i creds

until [ "$(kubectl -n e2e get podtracesession s3-sidecar -o jsonpath='{.status.state}')" = "Completed" ]; do sleep 3; done
kubectl -n e2e get podtracesession s3-sidecar \
  -o jsonpath='{range .status.conditions[*]}{.type}={.status}/{.reason}{"\n"}{end}'

kubectl -n e2e delete podtracesession s3-sidecar
```

Expect `report-uploader` listed as an initContainer, an
`objectstore-credentials` volume mounted, and a
`ReportUploaded=False/ObjectStoreUploadFailed` condition after the
session completes (the upload fails because the dummy S3 endpoint is
unreachable — exactly what the sidecar is supposed to surface).

## PodTraceSchedule (recurring + manual trigger)

Goal: all three concurrency policies, suspend gate, history GC, CLI
trigger with `--force` and `--print-only`, cascade delete.
Full reference: [crd-podtraceschedule.md](crd-podtraceschedule.md).

```bash
cat <<'EOF' | kubectl -n e2e apply -f -
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSchedule
metadata: { name: sched-allow }
spec:
  schedule: "* * * * *"
  concurrencyPolicy: Allow
  maxActiveSessions: 3
  successfulSessionsHistoryLimit: 2
  sessionTemplate:
    spec:
      selector: { matchLabels: { app: web } }
      duration: 15s
      filters: [dns]
      exporterRef: { name: ec-otlp }
---
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSchedule
metadata: { name: sched-forbid }
spec:
  schedule: "* * * * *"
  concurrencyPolicy: Forbid
  successfulSessionsHistoryLimit: 2
  sessionTemplate:
    spec:
      selector: { matchLabels: { app: web } }
      duration: 90s
      filters: [dns]
      exporterRef: { name: ec-otlp }
---
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSchedule
metadata: { name: sched-replace }
spec:
  schedule: "* * * * *"
  concurrencyPolicy: Replace
  successfulSessionsHistoryLimit: 1
  sessionTemplate:
    spec:
      selector: { matchLabels: { app: web } }
      duration: 90s
      filters: [dns]
      exporterRef: { name: ec-otlp }
EOF

# Wait ~3 minutes so policies have run multiple times
echo "Waiting ~3 minutes for runs..."
sleep 200

echo "=== Allow: bounded by successfulSessionsHistoryLimit=2 ==="
kubectl -n e2e get podtracesession -l podtrace.io/schedule=sched-allow

echo "=== Forbid: runs skipped while previous still active ==="
kubectl -n e2e get podtracesession -l podtrace.io/schedule=sched-forbid
kubectl -n e2e get podtraceschedule sched-forbid -o jsonpath='{.status.conditions[?(@.type=="Reconciled")].message}{"\n"}'

echo "=== Replace: at most 1 active at a time ==="
kubectl -n e2e get podtracesession -l podtrace.io/schedule=sched-replace
```

Suspend + CLI trigger:

```bash
kubectl -n e2e patch podtraceschedule sched-allow --type=merge -p '{"spec":{"suspend":true}}'
sleep 3
kubectl -n e2e get podtraceschedule sched-allow -o jsonpath='{.status.conditions[?(@.type=="Paused")]}{"\n"}'

# Refuses without --force
/tmp/podtrace schedule trigger sched-allow -n e2e            # expected: clean error, exit 1
echo "exit: $?"

# --force creates a session anyway
/tmp/podtrace schedule trigger sched-allow -n e2e --force
kubectl -n e2e get podtracesession -l podtrace.io/trigger=manual

# Dry-run prints the YAML, doesn't apply (works on suspended too)
/tmp/podtrace schedule trigger sched-allow -n e2e --print-only | head -20
```

Cascade delete:

```bash
kubectl -n e2e get podtracesession -l podtrace.io/schedule=sched-replace --no-headers | wc -l
kubectl -n e2e delete podtraceschedule sched-replace
sleep 5
kubectl -n e2e get podtracesession -l podtrace.io/schedule=sched-replace --no-headers | wc -l   # expect 0

kubectl -n e2e delete podtraceschedule sched-allow sched-forbid
kubectl -n e2e delete podtracesession --all
```

## Bundle versioning

Goal: the exporter bundle ConfigMap carries a `version` field. Internal
operator↔Job ABI — visible via `kubectl get cm`.

```bash
cat <<'EOF' | kubectl -n e2e apply -f -
apiVersion: podtrace.io/v1alpha1
kind: PodTrace
metadata: { name: bundle-check }
spec:
  selector: { matchLabels: { app: web } }
  exporterRef: { name: ec-otlp }
EOF
sleep 5

BUNDLE=$(kubectl -n podtrace-system get cm -l podtrace.io/exporter-config=ec-otlp -o name | head -1)
kubectl -n podtrace-system get "$BUNDLE" -o jsonpath='{.data.version}{"\n"}'

kubectl -n e2e delete podtraces.podtrace.io bundle-check
```

Expect: `v2`.

## ExporterConfig status reconciler

Goal: `.status.referencedBy` reflects live referent count, and the
REFS column on `kubectl get exporterconfig` is accurate. Full
reference: [crd-exporterconfig.md](crd-exporterconfig.md).

```bash
echo "=== before referents ==="
kubectl -n e2e get exporterconfig ec-otlp

cat <<'EOF' | kubectl -n e2e apply -f -
apiVersion: podtrace.io/v1alpha1
kind: PodTrace
metadata: { name: ref-trace }
spec:
  selector: { matchLabels: { app: web } }
  exporterRef: { name: ec-otlp }
---
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata: { name: ref-session }
spec:
  selector: { matchLabels: { app: web } }
  duration: 15s
  exporterRef: { name: ec-otlp }
EOF
sleep 8
echo "=== with 2 referents ==="
kubectl -n e2e get exporterconfig ec-otlp

kubectl -n e2e delete podtraces.podtrace.io ref-trace
sleep 6
echo "=== with 1 referent (after deleting the trace) ==="
kubectl -n e2e get exporterconfig ec-otlp

kubectl -n e2e delete podtracesession ref-session
sleep 10
echo "=== with 0 referents ==="
kubectl -n e2e get exporterconfig ec-otlp
```

Expect: REFS column transitions `<empty> → 2 → 1 → <empty>`.

## Chainsaw suite

The same checks (and more) automated:

```bash
chainsaw test --test-dir test/chainsaw/tests

# Or run one scenario:
chainsaw test --test-dir test/chainsaw/tests/schedule-cr-lifecycle
```

Expect: `Passed tests 12, Failed tests 0`.

## Final log scan

```bash
kubectl -n podtrace-system logs deploy/podtrace-operator --since=2h \
  | grep -iE '"level":"error"|panic|stacktrace' | head

for p in $(kubectl -n podtrace-system get pods -l podtrace.io/component=agent -o name); do
  echo "--- $p ---"
  kubectl -n podtrace-system logs "$p" --since=2h \
    | grep -iE '"level":"error"|panic' | head -5
done

kubectl -n podtrace-system get pods \
  -o custom-columns='NAME:.metadata.name,RESTARTS:.status.containerStatuses[*].restartCount'
```

Expect: empty everywhere, zero restarts.

## Teardown

```bash
kubectl delete ns e2e --wait=false
```

## Where to read the events you captured

This playbook only verifies *plumbing* — that Jobs run, statuses
populate, sidecars wire, conditions surface. To actually inspect what
the eBPF tracer captured during each run, see
[viewing-events.md](viewing-events.md).
