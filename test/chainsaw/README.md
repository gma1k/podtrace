# Chainsaw e2e suite

End-to-end tests for the podtrace operator, expressed as
[Chainsaw](https://kyverno.github.io/chainsaw/) test cases. Each
sub-directory under [`tests/`](tests/) is one test scenario; each is
independently runnable.

## Prerequisites

- A running Kubernetes cluster reachable via the current `KUBECONFIG`
  (kind is the expected target).
- Image `ghcr.io/podtrace/podtrace:dev` loaded into the cluster
  (`make docker-build IMAGE_TAG=dev && kind load docker-image …`).
- The operator already installed via Helm with the chart-rendered
  defaults (the smoke script `test/e2e/kind-smoke.sh` does this).
- `chainsaw` CLI on `$PATH`. Install:

  ```bash
  go install github.com/kyverno/chainsaw@latest
  ```

## Running

```bash
# Run the full suite
make chainsaw

# Run one test
chainsaw test --test-dir test/chainsaw/tests/session-cr-lifecycle

# Pass-through args
chainsaw test --test-dir test/chainsaw/tests --include-test-regex 'session.*'
```

Each test starts from a clean state by creating its own namespace.
Timeouts are conservative — a slow kind cluster can take 90s+ for the
session lifecycle test to complete.

## Tests

| Test | What it covers |
|---|---|
| [continuous-cr-lifecycle](tests/continuous-cr-lifecycle) | `PodTrace` CR create / update filters / delete cleanly. Asserts bundle materialization in `podtrace-system`, finalizer cleanup. |
| [session-cr-lifecycle](tests/session-cr-lifecycle) | `PodTraceSession` runs a real eBPF diagnose, reaches `Completed`, populates `status.summary` and the `reportRef` ConfigMap. |
| [multi-cr-shared-agent](tests/multi-cr-shared-agent) | Two `PodTrace` CRs targeting overlapping pods produce one tracer process; both report Ready independently. |
| [agent-restart-resilience](tests/agent-restart-resilience) | Restart the agent DaemonSet; existing CRs stay healthy and per-node status reappears. **Control-plane only** — does not assert event continuity (Phase 5+ work). |
| [exporter-credential-rotation](tests/exporter-credential-rotation) | Update an upstream `ExporterConfig` Secret; operator refreshes the bundle Secret in `podtrace-system`. **Control-plane only** — does not assert delivery to a real receiver (Phase 7+ work). |
| [psa-enforcement](tests/psa-enforcement) | PSA `enforce: privileged` admits agent pods in `podtrace-system` and rejects equivalent pod specs in a `restricted` namespace. |

## Honest scope notes

Two tests are intentionally control-plane only:

- **agent-restart-resilience** — the agent's continuous path uses
  `NoopBackend` today; events do not actually flow through the agent
  to the exporter. The test verifies the control plane (CRs stay
  Ready, status reappears, bundles still mounted, finalizers don't
  trigger spurious cleanup) but cannot verify event continuity.
- **exporter-credential-rotation** — without a mock OTLP receiver, we
  cannot assert that the rotated credential reaches the receiver. The
  test verifies the operator's refresh path: upstream Secret edit →
  bundle Secret in `podtrace-system` carries the new credential.

Wiring real eBPF events through the agent's continuous loop is Phase
5+ work. A mock OTLP receiver pod that records request headers is
Phase 7+ work. Once those land, tighter assertions move from
"control-plane updated" to "rotated credential observed at receiver".
