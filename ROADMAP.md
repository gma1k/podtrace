# Roadmap

What podtrace intends to work on next, and what it does not intend to build.

This document is deliberately coarse. It records **themes and rough
ordering**, not dates. For the mechanical rules about when versions move and
what a version promises, see [STABILITY.md](STABILITY.md). For what already
shipped, see [CHANGELOG.md](CHANGELOG.md).

## How to read this

- **No dates and no quarters.** Ordering expresses intent, not commitment. A
  roadmap with slipped quarters is worse than no roadmap.
- **Version gates are not here.** The conditions for `v1beta1` and `v1.0.0`
  are defined in [STABILITY.md](STABILITY.md). This document says what work
  moves toward them.

## Where podtrace is today

| | |
|---|---|
| Current line | `v0.14.x`, pre-1.0 |
| CRDs | 6, all at `podtrace.io/v1alpha1` |
| End-to-end suites | 22 chainsaw scenarios |
| Architectures | amd64 and arm64, both first-class and CI tested |
| Minimum kernel | 5.8, with 6.1+ recommended |
| Minimum Kubernetes | 1.28, with 1.32 to 1.36 recommended |

Full support matrix, including which probes need BTF, is in
[docs/compatibility.md](docs/compatibility.md).

## Now

Small, well-defined work that unblocks the larger items below.

1. **Reconcile the CRD inventory.** [STABILITY.md](STABILITY.md) describes
   four CRDs. There are six: `PodTrace`, `PodTraceSession`,
   `PodTraceSchedule`, `ExporterConfig`, `TracerConfig`, and
   `ApplicationTrace`. The `v1.0.0` criteria inherit the same undercount and
   need the same correction.

2. **Publish a per-CRD `v1beta1` readiness table.** The three graduation
   gates already exist in [STABILITY.md](STABILITY.md). What is missing is an
   honest assessment of each CRD against them, so adopters can see which
   parts of the API are close to stable and which are still moving.

3. **Finish the supply-chain baseline.** OpenSSF Scorecard now runs and
   publishes. Remaining: SLSA provenance attached to releases, and an
   [OpenSSF Security Insights](https://github.com/ossf/security-insights-spec)
   manifest that states the inherent risk of a privileged kernel-level agent
   in terms a security review can consume.

## Next

4. **A formal API deprecation policy.** [STABILITY.md](STABILITY.md) lists
   this as a condition for `v1.0.0` but does not yet define it. It needs to
   say how long a deprecated field or CRD version is served, how deprecation
   is announced, and what an adopter is entitled to rely on.

5. **Graduate the CRDs that clear their gates to `v1beta1`,** served
   alongside `v1alpha1` during transition. Graduation is per-CRD, so this
   lands incrementally rather than as one event.

6. **Decide the conversion story.** Today podtrace ships no conversion
   webhooks and expects adopters to edit manifests by hand. Serving
   `v1alpha1` and `v1beta1` simultaneously makes that choice load-bearing, so
   it needs to be either committed to explicitly or replaced with conversion.

7. **Make the Go API usable from outside.** `api/v1alpha1` and `pkg/client`
   are importable, which means anyone can build a controller or integration
   against podtrace CRs. Runnable godoc examples are the cheapest way to make
   that real, and `go test` keeps them from rotting.

## Later

8. **`v1.0.0`,** once the four conditions in [STABILITY.md](STABILITY.md)
   hold. This is downstream of everything above and is not near.

9. **State platform support in tiers.** [docs/compatibility.md](docs/compatibility.md)
   already documents what is required. The gap is a clear statement of what
   is CI-verified against what is best-effort, particularly for kernels
   without BTF, where a meaningful subset of probes is unavailable.

10. **Project sustainability.** Podtrace has one maintainer. That is the
    single largest risk to anyone adopting it, more than any individual
    feature, and it is worth naming plainly rather than leaving implicit. A
    second maintainer with real review authority is the goal.

## Non-goals

Things podtrace is not trying to become. These are as useful to adopters as
the list above, and they are open to challenge in
[Discussions](https://github.com/gma1k/podtrace/discussions) if your use case
argues otherwise.

- **Not a non-Linux agent.** The tracing core is eBPF, so it is Linux-kernel
  bound by construction.
- **Not a policy engine, admission controller, or service mesh.** Podtrace
  observes workloads. It does not admit, mutate, or route them.
- **No agent self-update.** Agent version is whatever the operator deploys,
  so upgrades stay under the cluster owner's control.

## Influencing this

Open an [issue](https://github.com/gma1k/podtrace/issues) for something
concrete, or start a [discussion](https://github.com/gma1k/podtrace/discussions)
for a direction. Adopter reports carry the most weight in reordering this
list, especially from anyone running podtrace against real traffic.

## Related documents

- [STABILITY.md](STABILITY.md), what each version promises and the gates for
  `v1beta1` and `v1.0.0`
- [CHANGELOG.md](CHANGELOG.md), what already shipped
- [GOVERNANCE.md](GOVERNANCE.md), how decisions get made
- [CONTRIBUTING.md](CONTRIBUTING.md), how to work on any of the above
- [docs/compatibility.md](docs/compatibility.md), kernel, Kubernetes, and
  architecture support