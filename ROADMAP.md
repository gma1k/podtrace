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
| End-to-end suites | 23 chainsaw scenarios |
| Architectures | amd64 and arm64, both first-class and CI tested |
| Minimum kernel | 5.8, with 6.1+ recommended |
| Minimum Kubernetes | 1.28, with 1.32 to 1.36 recommended |

Full support matrix, including which probes need BTF, is in
[docs/compatibility.md](docs/compatibility.md).

## Now

Small, well-defined work that unblocks the larger items below.

1. **Publish a per-CRD `v1beta1` readiness table.** The three graduation
   gates already exist in [STABILITY.md](STABILITY.md). What is missing is an
   honest assessment of each CRD against them, so adopters can see which
   parts of the API are close to stable and which are still moving.

2. **Keep using the `v1alpha1` cleanup window.** A review of
   all six schemas landed in `v0.14.7`, unifying the names that had drifted
   apart. The window stays open until a CRD actually graduates, so anything
   still awkward can be fixed, but only until then, since `v1beta1` carries
   every field it inherits until `v1`. Two candidates were deliberately
   deferred rather than dropped: `TracerConfig.spec.systemNamespace`, which
   backs per-fleet namespace isolation and is a product question rather than
   a naming one, and `containerName`, which wants to be a list but threads
   through target resolution and the CLI flag surface. Rationale in
   [docs/api-versioning.md](docs/api-versioning.md).

3. **Finish the supply-chain baseline.** OpenSSF Scorecard now runs and
   publishes. Remaining: SLSA provenance attached to releases, and an
   [OpenSSF Security Insights](https://github.com/ossf/security-insights-spec)
   manifest that states the inherent risk of a privileged kernel-level agent
   in terms a security review can consume.

## Next

4. **Graduate the CRDs that clear their gates to `v1beta1`.** Graduation is
   per-CRD and spans two releases — add the new version and migrate stored
   objects, then retire the old one — so this lands incrementally rather
   than as one event. The first graduation is also the test of whether the
   procedure in [docs/api-versioning.md](docs/api-versioning.md) survives
   contact with a real cluster, so it should be a small CRD rather than
   `PodTrace`.

5. **Make the Go API usable from outside.** `api/v1alpha1` and `pkg/client`
   are importable, which means anyone can build a controller or integration
   against podtrace CRs. Runnable godoc examples are the cheapest way to make
   that real, and `go test` keeps them from rotting.

## Later

6. **`v1.0.0`,** once the four conditions in [STABILITY.md](STABILITY.md)
   hold. This is downstream of everything above and is not near.

7. **State platform support in tiers.** [docs/compatibility.md](docs/compatibility.md)
   already documents what is required. The gap is a clear statement of what
   is CI-verified against what is best-effort, particularly for kernels
   without BTF, where a meaningful subset of probes is unavailable.

8. **Project sustainability.** Podtrace has one maintainer. That is the
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
- [docs/api-versioning.md](docs/api-versioning.md), the CRD graduation
  contract, deprecation policy, and cutover procedure
- [docs/compatibility.md](docs/compatibility.md), kernel, Kubernetes, and
  architecture support