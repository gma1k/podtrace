# Contributing to Podtrace

Thanks for considering a contribution. This guide covers the local
development workflow, testing, commit conventions, and release process
so you can land a change with confidence.

For everything beyond this file:

- [README.md](README.md) — what podtrace does and the three usage patterns
- [STABILITY.md](STABILITY.md) — versioning policy and what the API
  promises (and doesn't) at `v0.x`
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — community behavioral standards
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [docs/](docs/) — full reference for installation, CRDs, eBPF internals,
  per-distro notes, and tracing exporters

## Project layout

```
api/v1alpha1/             Kubernetes CRD types (PodTrace, PodTraceSession,
                          ExporterConfig, TracerConfig)
bpf/                      eBPF C source (one-per-feature: network, filesystem,
                          cpu, memory, syscalls, fastcgi, grpc, ...)
cmd/podtrace/             Single Go entry point (CLI, agent, operator, session
                          Job, selected via subcommand)
internal/                 Implementation packages
  ebpf/embedded/          Per-arch embedded BPF objects + load helpers
  ebpf/loader/            Spec loading and fallback to embedded
  operator/               Reconcilers for the four CRDs
  agent/                  DaemonSet runtime (multi-CR merge router)
  config/, events/, ...   Shared internals
deploy/charts/podtrace/   Helm chart (CRDs, operator deployment, RBAC)
deploy/quickstart-sample.yaml  Demo workload + sample CRs concatenated
                          into the released `quickstart.yaml`
docs/                      User documentation
test/                     Integration tests + chainsaw e2e suite
.github/workflows/        CI workflows (per-PR + release pipeline)
```

## Module path vs GitHub repo location

The Go module path and the GitHub repo location must agree. `github.com` is one of a
handful of hosts with a resolution rule built into the go command, so
`github.com/<owner>/<repo>` always resolves to literally that repository. The
`go-import` meta tag, the only mechanism that can point an import path elsewhere,
applies solely to custom domains. There is no way to alias one GitHub path to another.

| Concept | Value | Why it has this value |
|---|---|---|
| **Go module path** | `github.com/gma1k/podtrace` | Declared in `go.mod` and used as the import prefix in every `.go` file. Must match the repo location, or the module cannot be fetched by `go get`, `go install`, or pkg.go.dev. |
| **GitHub repo location** | `github.com/gma1k/podtrace` | Where the project lives. |
| **Container/chart registry** | `ghcr.io/gma1k/podtrace`, `ghcr.io/gma1k/charts/podtrace` | Tracks the GitHub org. |

If podtrace ever moves to a `podtrace` GitHub org, the module path has to move with
it: `go.mod`, every import statement, `MODULE` in the `Makefile`, and the `-ldflags`
paths in the `Dockerfile`. Because that rename breaks every external importer, it
also needs a major version bump once the project is past v1.

If you want an import path that survives relocation, the only supported way is a
vanity path such as `podtrace.io/podtrace`, served by a `go-import` meta tag on a
domain the project controls. That decouples the import path from the host
permanently, at the cost of the domain becoming load-bearing for every build.

## Local development

### One-shot setup

```bash
git clone https://github.com/gma1k/podtrace.git
cd podtrace

# Install build dependencies (Debian/Ubuntu)
sudo ./scripts/install-deps.sh

# Or manually
sudo apt-get install -y clang llvm libbpf-dev libelf-dev make pkg-config

# Pull Go modules
make deps

# Build the eBPF object + Go binary
make build

# Sanity check
./bin/podtrace --version
```

For per-distro specifics (AKS, EKS, GKE, OpenShift, Talos), see the
guides in [docs/](docs/).

### Iterating

| Command | What it does |
|---|---|
| `make build` | Compiles the per-arch BPF object + the Go binary with `-tags embed_bpf` |
| `make clean` | Removes built artifacts including all `internal/ebpf/embedded/*.bpf.o` and `bin/` |
| `make build BPF_GOARCH=arm64` | Cross-compile the BPF object for arm64 (Go binary stays host-arch) |

## Testing

Podtrace has multiple test layers, each catching different bug classes.
On a PR, CI runs all of them; locally you typically only need the fast
unit tests.

| Layer | Command | Speed | What it catches |
|---|---|---|---|
| **Unit tests** | `make test` (alias `make test-fast`) | ~30s | Most logic regressions; default for iterating |
| **Unit tests with race** | `make test-unit` | ~1 min | Data races; the canonical pre-PR check |
| **Integration tests** | `make test-integration` | ~2 min | Cross-package interactions tagged `integration` |
| **envtest (CRD round-trip)** | `make envtest` | ~3 min | CRD schema validation, webhook behavior, controller wiring against a real apiserver+etcd |
| **eBPF embed smoke** | `go test -tags embed_bpf ./internal/ebpf/embedded/...` | ~5s | Per-arch embed file missing or pointing at non-existent BPF object (only meaningful after `make build`) |
| **Chainsaw e2e** | `make chainsaw` | ~10 min | Full end-to-end: kind cluster, real BPF load in kernel, CRD reconciliation, Job lifecycle |
| **kind smoke** | `make e2e-kind` (cleanup: `make e2e-kind-cleanup`) | ~3 min | Lighter-weight kind smoke without chainsaw |
| **Helm chart lint** | `make helm-lint` | ~5s | Chart YAML / template validity |
| **Coverage** | `make coverage` | ~30s | Generates `coverage.out` + `coverage.html` |

Recommended pre-PR:

```bash
make test-unit && make lint && make helm-lint && make build
```

If your change touches BPF probes, RBAC, or the operator reconcilers, run
`make chainsaw` too — these are the bug classes that only surface in a
real cluster.

## Code style

Formatting and linting are enforced by tooling, not by review comments. Run
them locally and you will not be surprised by CI.

| What | Command | Enforced by |
|---|---|---|
| Go lint | `make lint` | `go-ci.yml` (blocks merge) |
| Go format | `make fmt` (check only: `make fmt-check`) | Not gated in CI — see the note below |
| Shell | `shellcheck --enable=all -x $(git ls-files '*.sh')` | `bash-checks.yml` (blocks merge) |
| Shell format | `shfmt -d .` (fix: `shfmt -w .`) | `bash-checks.yml` (blocks merge) |
| Shell portability | `checkbashisms $(git ls-files '*.sh')` | `bash-checks.yml` (blocks merge) |
| Helm chart | `make helm-lint` | Chart changes |
| Whitespace / EOL | `.editorconfig` | Your editor |
| DCO sign-off | `git commit -s` | `dco.yml` (blocks merge) |

### Go

`make lint` runs **golangci-lint v2.13.0** — the same version CI pins — against
[`.golangci.yml`](.golangci.yml), which selects the v2 `standard` linter set:
`errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`. Because both the
version and the linter set are pinned in-repo, a clean `make lint` locally means
a clean lint job in CI.

> **Do not install golangci-lint with `go install`.** golangci-lint v2.13.0
> declares `go 1.26.0`, so `go install` builds it with a Go 1.26 toolchain, and
> the resulting binary refuses to run against this module:
> `the Go language version (go1.26) used to build golangci-lint is lower than
> the targeted Go version (1.27.0)`. It fails with or without a config file.
> `make lint` avoids this by downloading the official prebuilt release binary
> (built with Go 1.27) into `bin/`, checksum-verified against the release's
> `checksums.txt`.

Formatting is plain `gofmt` — `make fmt` is `go fmt ./...`. It is deliberately
**not** a CI gate: enabling gofmt as a linter would fail the build on
pre-existing files rather than on your change. Keep the files you touch
gofmt-clean; `make fmt-check` lists everything currently non-conforming.

If your editor strips the final newline on save, gofmt will flag the file. Make
sure "insert final newline" is enabled — `.editorconfig` already requests it
(`insert_final_newline = true`).

### eBPF C

The code under `bpf/` follows Linux kernel style: tabs, 8-column indent width,
as encoded in `.editorconfig`. There is no automated C formatter in CI, so match
the surrounding file. Keep helpers `static __always_inline`, and remember the
verifier reads your control flow — see
[docs/ebpf-internals.md](docs/ebpf-internals.md).

### Shell

`bash-checks.yml` runs `shellcheck --enable=all`, which turns on optional checks
most projects leave off, plus `checkbashisms` and `shfmt -d`, over every tracked
`*.sh`. Run all three before pushing a script — this job blocks merges and
`--enable=all` will flag things a default shellcheck run does not.

### Everything else

[`.editorconfig`](.editorconfig) is the cross-editor baseline: UTF-8, LF endings,
final newline, trailing whitespace trimmed. Markdown is the one exception —
trailing whitespace is preserved there, because two trailing spaces is a hard
line break.

Comments should explain *why*, not restate *what*. Public functions get doc
comments; non-obvious kernel or Kubernetes behavior gets a sentence explaining
the constraint that forced the code into its shape.

## Commit conventions

Podtrace uses [Conventional Commits](https://www.conventionalcommits.org/)
so [release-please](https://github.com/googleapis/release-please) can
automatically maintain `CHANGELOG.md` and propose version bumps.

Format: `<type>(<optional scope>): <subject>`. Subject in imperative mood,
no trailing period, ≤ 72 chars.

| Type | Visible in changelog? | Effect on version (pre-1.0) |
|---|---|---|
| `feat:` | ✅ Features section | patch bump |
| `fix:` | ✅ Bug Fixes section | patch bump |
| `perf:` | ✅ Performance section | patch bump |
| `security:` | ✅ Security section | patch bump |
| `deprecate:` | ✅ Deprecated section | patch bump |
| `remove:` | ✅ Removed section | patch bump |
| `revert:` | ✅ Maintenance section | patch bump |
| `refactor:`, `chore:`, `docs:`, `style:`, `test:`, `build:`, `ci:` | ❌ Hidden in CHANGELOG, ✅ shown on Release page | no bump |
| Title suffix `feat!:` / footer `BREAKING CHANGE:` | ✅ ⚠ BREAKING CHANGES section | **minor bump** (your only path to `v0.X+1.0`) |
| Footer `Release-As: 0.X.Y` | overrides version explicitly | Forces release-please to propose the named version |

A few notes on type choice:

- **One PR = one type.** Pick the type that matches the PR's dominant
  intent and stick with it. release-please reads only the squash-merge
  subject line — sub-bullets in the PR body do *not* get categorised.
  Mixed-intent PRs should be split.
- **`refactor:` is hidden** because, by definition, a refactor has no
  user-visible behaviour change. If the change *does* affect a public
  surface (CLI flag, CRD field, env var, Helm value), it is not a
  refactor — use `feat:` or `feat!:` / `BREAKING CHANGE:`.
- **`deprecate:` vs `remove:`** — deprecating something keeps it
  working for one or more releases with a warning; removing it
  breaks the contract. A removal should usually carry a
  `BREAKING CHANGE:` footer too, so the minor-version bump signals
  the contract change.
- **`security:` and `deprecate:` / `remove:` are project-specific
  extensions** to the standard Conventional Commits vocabulary. They
  exist because Keep-a-Changelog defines Security / Deprecated /
  Removed sections that the upstream spec has no native types for.
- **CHANGELOG.md sections align with the enriched Release page** —
  both use Features / Bug Fixes / Performance / Security / Deprecated
  / Removed / Maintenance. The Release page additionally surfaces the
  types hidden from CHANGELOG (Documentation, Tests, CI/Build), which
  is why the two artifacts look similar but not identical.

Examples:

```
feat(cli): add --json output mode

Closes #123
```

```
fix(loader): handle missing BTF file gracefully

When /sys/kernel/btf/vmlinux is absent, fall back to the embedded
BPF object instead of erroring on load.
```

```
deprecate(api): spec.legacySelector is replaced by spec.selector

spec.legacySelector keeps working in 0.x but emits a warning event
on every reconcile. It will be removed in v1.0.0; switch to
spec.selector now.
```

```
remove(api): drop spec.legacySelector

BREAKING CHANGE: spec.legacySelector was deprecated in 0.10 and is
now removed. Use spec.selector. Existing CRs that still set
legacySelector will fail admission until updated.
```

```
perf(agent): hash cgroup IDs with xxh3 instead of sha256

Reduces per-event hashing overhead by ~70% on hot paths.
```

The bump rules above apply pre-1.0. After `v1.0.0`, the standard semver
mapping kicks in (`feat:` → minor, `BREAKING CHANGE:` → major). See
[STABILITY.md](STABILITY.md) for the full versioning policy and the
graduation criteria from `v0.x` to `v1.0.0`.

## Developer Certificate of Origin

Every commit must carry a Developer Certificate of Origin (DCO) sign-off.
The DCO is a short assertion, reproduced in full at
[developercertificate.org](https://developercertificate.org/), that you have
the right to submit the code under this project's Apache-2.0 licence. There
is no CLA, no account to create, and nothing to sign out of band: the
sign-off lives in the commit message itself.

Add it with `-s`:

```bash
git commit -s -m "fix(loader): handle missing BTF file gracefully"
```

Git appends a trailer built from your `user.name` and `user.email`:

```
Signed-off-by: Jane Developer <jane@example.com>
```

By adding it you are asserting three things:

- You wrote the code, or you have the right to submit it under Apache-2.0
- If your employer owns the copyright in your work, you have their
  permission to contribute it
- You understand the commit, including the name and email in the trailer,
  is public and permanent

So make sure your identity is set before you start:

```bash
git config user.name "Jane Developer"
git config user.email "jane@example.com"
```

### Forgot the sign-off

The trailer must match the commit author's email, so amend rather than add a
separate commit:

```bash
git commit --amend -s --no-edit          # most recent commit
git rebase --signoff origin/main         # every commit on the branch
git push --force-with-lease
```

`dco.yml` checks every commit in a pull request and blocks the merge until
they all pass. Sign-offs survive the squash merge, because squash commit
bodies are built from the individual commit messages. Machine-generated
commits from bot accounts (renovate, `github-actions`) are exempt: a bot
cannot make the DCO assertion, and release-please branches skip the job
entirely.

## How releases happen

The release pipeline is fully automated once a release-worthy commit
lands on `main`:

```
1. You merge a PR with a non-hidden commit type (feat:/fix:/perf:/deprecate:/remove:/security:/revert:)
   ↓
2. release-please opens a "chore(main): release X.Y.Z" PR
   - Updates CHANGELOG.md
   - Bumps .release-please-manifest.json
   - Bumps Chart.yaml appVersion (via the marker comment)
   ↓
3. Maintainer reviews the proposed changelog and merges
   ↓
4. release-please creates the v0.X.Y tag (via RELEASE_PLEASE_PAT)
   ↓
5. release.yml fires automatically:
   - image      → ghcr.io/gma1k/podtrace:0.X.Y  (multi-arch, signed, SBOM, provenance)
   - chart      → oci://ghcr.io/gma1k/charts/podtrace:0.1.Z  (signed)
   - quickstart → quickstart.yaml on the GitHub Release
   - cli        → podtrace_<os>_<arch>.tar.gz × 4 + checksums + cosign bundle
```

Zero manual clicks per release. All artifacts are cosign-signed keyless
and recorded in the [Sigstore Rekor transparency log](https://search.sigstore.dev/).

### Cutting a minor or major release

The flow above describes patch releases, where release-please reacts to
each `feat:`/`fix:` merge on `main`. For minor (`0.Y.0`) and major
(`X.0.0`) cuts, use the manual trigger so the version bump is intentional:

1. **Actions → "Release-As" → Run workflow**, enter the target version (e.g. `0.12.0`)
2. release-please opens a `chore(release): release X.Y.Z` PR; review and merge it
3. After the tag is created, `release-notes-enrich.yml` fires automatically
   and overwrites the GitHub Release body with the full cross-minor PR list
   grouped per [`.github/release.yml`](.github/release.yml)

The enriched Release body is broader than `CHANGELOG.md` — it includes
docs, test, CI, build, and maintenance PRs that are intentionally hidden
from the user-facing changelog. Two artifacts, two audiences.

PRs also receive an `area/*` label automatically based on the paths they
touch (driven by [`.github/labeler.yml`](.github/labeler.yml)) — e.g. a
PR editing `internal/operator/**` gets `area/operator`. Filter merged
work with `gh pr list --label area/bpf` etc. Area labels are independent
of the conventional-commit type label and do not affect release-note
grouping.

If the auto-computed previous tag is wrong (e.g. you want to span more
than one minor), re-run `release-notes-enrich.yml` manually with both
inputs filled in. Patch releases skip enrichment entirely and keep
release-please's per-patch body.

### Rehearsing the release pipeline

To exercise the workflow without burning a real version, push a tag
prefixed with `test`:

```bash
git tag test-2026-05-15
git push origin test-2026-05-15
```

The workflow's `cli` job runs and uploads tarballs to a Pre-release
GitHub Release. The `image`, `chart`, and `quickstart` jobs are guarded
to run only on `v*` tags, so they skip — no public artifacts pushed for
test tags.

## Pull request checklist

Before opening a PR:

- [ ] Every commit is signed off (`git commit -s`) per the DCO section above
- [ ] Commit message follows Conventional Commits (drives release-please)
- [ ] Tests pass: at minimum `make test-unit`; `make chainsaw` for BPF/operator/agent changes
- [ ] Updated relevant docs in `docs/` if you changed user-visible behavior
- [ ] If touching public surface (CRDs, CLI flags, Helm values, env vars), reviewed [STABILITY.md](STABILITY.md) and called out any breaking change in the commit footer
- [ ] If adding a new BPF probe or feature, considered the kernel-version pitfalls documented in [docs/compatibility.md](docs/compatibility.md)

## Where to ask

- **Issues**: [github.com/gma1k/podtrace/issues](https://github.com/gma1k/podtrace/issues) — bugs, feature requests, epics. Blank issues are disabled; pick a template.
- **Questions**: [Discussions → Q&A](https://github.com/gma1k/podtrace/discussions/categories/q-a) — usage, kernel support, "why no events"
- **Ideas**: [Discussions → Ideas](https://github.com/gma1k/podtrace/discussions/categories/ideas) — design direction before it is a concrete request
- **Vulnerabilities**: see [SECURITY.md](SECURITY.md) for the private reporting flow
- **Governance**: see [GOVERNANCE.md](GOVERNANCE.md) for how decisions get made and how to become a maintainer