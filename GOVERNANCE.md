# Governance

Podtrace is maintainer-led. This document describes how decisions actually get
made today, so contributors can predict what will happen to their work. It is
deliberately lightweight and will grow as the project does.

## Roles

**Contributors** are anyone who opens an issue, answers a question in
Discussions, improves docs, or sends a pull request. No formal status is
required and none is conferred.

**Maintainers** hold merge rights and are listed in
[MAINTAINERS.md](MAINTAINERS.md), with per-path authority encoded in
[CODEOWNERS](CODEOWNERS).

## How decisions get made

Most decisions are made in the open on the pull request or issue that proposes
them. The bar scales with how hard the change is to reverse:

| Change | Path |
|---|---|
| Bug fix, docs, tests, dependency bump | PR with CODEOWNERS approval |
| New feature, new probe, new adapter | Feature request or epic issue first, so the shape is agreed before the code |
| Public surface — CRDs, CLI flags, Helm values, env vars | Feature request plus an explicit read of [STABILITY.md](STABILITY.md); breaking changes need `!` in the commit subject and a migration note |
| Security fix | Private, under [SECURITY.md](SECURITY.md), until an advisory ships |

Disagreements are resolved by discussion on the thread. Where consensus is not
reached, maintainers decide, and are expected to state the reasoning in the
thread rather than merging silently.

## Proposing larger work

1. Open a thread in [Discussions → Ideas](https://github.com/gma1k/podtrace/discussions/categories/ideas)
   if the direction is still open-ended.
2. Once the scope is clear, open a feature request, or an
   [epic](https://github.com/gma1k/podtrace/issues/new?template=epic.yml) if it
   spans several PRs.
3. Land it incrementally. Long-lived branches are discouraged — this project
   carries eBPF programs whose kernel assumptions drift.

## Becoming a maintainer

There is no application form. Maintainership follows demonstrated work:

- A track record of merged, non-trivial contributions.
- Reviews that catch real problems, especially in eBPF or Kubernetes-facing code.
- Judgment about compatibility — kernel-version pitfalls
  ([docs/compatibility.md](docs/compatibility.md)) and the stability promises in
  [STABILITY.md](STABILITY.md).
- Sustained engagement, rather than a single large drop of code.

Existing maintainers extend the invitation. Anyone stepping back is moved to an
emeritus note in [MAINTAINERS.md](MAINTAINERS.md) rather than deleted — the
history is worth keeping.

## Licensing and provenance

Contributions are accepted under the licenses already in the tree: Apache-2.0
for Go and project files, GPL-2.0 for the eBPF programs under `bpf/`. Do not
contribute code you cannot license accordingly.

## Changing this document

Governance changes go through the same PR process as code, and should be
proposed as their own PR rather than folded into a feature branch.