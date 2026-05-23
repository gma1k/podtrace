# Getting Help

Podtrace is maintained as an open-source project on GitHub. There is no
paid support channel; everything happens in the public repo so the
answers help the next person too.

## Pick the right channel

| What you want | Where to go |
|---|---|
| **Bug report** — something is broken or behaves unexpectedly | Open an issue with the [bug report template](https://github.com/gma1k/podtrace/issues/new?template=bug_report.yaml). Include `kubectl version`, kernel version (`uname -r`), the failing CR YAML, and operator/agent logs. |
| **Feature request** — you want podtrace to do something new | Open an issue with the [feature request template](https://github.com/gma1k/podtrace/issues/new?template=feature_request.yaml). Describe the use case first, the proposed shape second. |
| **Epic** — multi-step initiative spanning several PRs | Open an issue with the [epic template](https://github.com/gma1k/podtrace/issues/new?template=epic.yaml). |
| **Are you using podtrace?** | Tell us via the [adopters template](https://github.com/gma1k/podtrace/issues/new?template=adopters.yaml). |
| **Question / general discussion** — "how do I…", "is X the right approach…" | Open an issue with a `[discussion]` prefix in the title. Per [CONTRIBUTING.md](CONTRIBUTING.md), this is the project's lightweight discussion channel until a separate Discussions tab is enabled. |
| **Security vulnerability** | **Do not open a public issue.** Follow the disclosure process in [SECURITY.md](SECURITY.md). |

## Before opening a bug

A few minutes of self-diagnosis usually shortens the round-trip by days:

1. **Versions** — confirm your stack meets the floor in
   [docs/compatibility.md](docs/compatibility.md): kernel 5.8+, BTF
   available, Kubernetes 1.28+.
2. **Read the agent's own diagnostic surface** before logs:
   - `kubectl describe podtrace <name>` — the `Degraded` condition and
     each `nodeStatus[*].reason` carry a closed-enum reason
     (`BackendUnavailable`, `ExporterBuildFailed`, `BundleLoadFailed`,
     …) that usually points straight at the cause.
   - `kubectl get --raw /api/v1/namespaces/podtrace-system/services/podtrace-agent:9090/proxy/metrics`
     (or port-forward the agent's `:9090`) to inspect
     `podtrace_agent_backend_degraded`,
     `podtrace_agent_program_attach_failures_total`, and
     `podtrace_agent_exporter_init_failures_total`.
3. **Reproduce minimally** — strip your CR down to the smallest form
   that still shows the bug, and include it verbatim in the issue.
4. **Logs** — `kubectl logs -n podtrace-system ds/podtrace-agent
   --tail=200` and the same for `deploy/podtrace-operator`. Include the
   surrounding ~50 lines, not just the error.

## Documentation pointers

If you're not sure where a topic lives:

- **Installation**, env-vars, troubleshooting → [docs/installation.md](docs/installation.md)
- **Per-distro quirks** (AKS, EKS, GKE, OpenShift, Talos) → linked from
  [docs/compatibility.md](docs/compatibility.md)
- **CRD reference** → `docs/crd-*.md`
- **Architecture** → [docs/architecture.md](docs/architecture.md)
- **eBPF internals** → [docs/ebpf-internals.md](docs/ebpf-internals.md)
- **Metrics reference** → [docs/operator.md#observability](docs/operator.md)
  for agent + operator metrics; [docs/metrics.md](docs/metrics.md) for
  the CLI surface

## What we cannot help with

- **Debugging your application** — podtrace surfaces kernel-level
  signals; interpreting them in the context of your service is on you.
- **Setting up cert-manager, OTel Collector, Prometheus** — covered by
  their upstream docs; we link the integration points but the
  components themselves are out of scope.
- **Backporting** — only the latest minor release line receives fixes.
  See [STABILITY.md](STABILITY.md) for the support window.
