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
- [doc/](doc/) — full reference for installation, CRDs, eBPF internals,
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
doc/                      User documentation
test/                     Integration tests + chainsaw e2e suite
.github/workflows/        CI workflows (per-PR + release pipeline)
```

## Module path vs GitHub repo location

A small but important distinction for contributors:

| Concept | Value | Why it has this value |
|---|---|---|
| **Go module path** | `github.com/podtrace/podtrace` | Declared in `go.mod`. Used as the import prefix in every `.go` file. Frozen — changing it would require updating every import statement across the codebase. |
| **GitHub repo location** | `github.com/gma1k/podtrace` | Where the project actually lives today. Tracks the maintainer's account. |
| **Container/chart registry** | `ghcr.io/gma1k/podtrace`, `ghcr.io/gma1k/charts/podtrace` | Tracks the GitHub org. |

If/when podtrace migrates to a `podtrace` GitHub org (or any other location), the GitHub URLs and registry paths change but the **Go module path stays the same**. This is intentional: import statements are stable, repo URLs are not. Don't be surprised when you see `import "github.com/podtrace/podtrace/..."` in code that lives at `github.com/gma1k/podtrace` — they're two different identifiers serving two different purposes.

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
guides in [doc/](doc/).

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
make test-unit && make helm-lint && make build
```

If your change touches BPF probes, RBAC, or the operator reconcilers, run
`make chainsaw` too — these are the bug classes that only surface in a
real cluster.

## Commit conventions

Podtrace uses [Conventional Commits](https://www.conventionalcommits.org/)
so [release-please](https://github.com/googleapis/release-please) can
automatically maintain `CHANGELOG.md` and propose version bumps.

Format: `<type>(<optional scope>): <subject>`. Subject in imperative mood,
no trailing period, ≤ 72 chars.

| Type | Visible in changelog? | Effect on version (pre-1.0) |
|---|---|---|
| `feat:` | ✅ Added section | patch bump |
| `fix:` | ✅ Fixed section | patch bump |
| `refactor:`, `perf:`, `revert:` | ✅ Changed section | patch bump |
| `chore:`, `docs:`, `style:`, `test:`, `build:`, `ci:` | ❌ Hidden | no bump |
| `security:` | ✅ Security section | patch bump |
| Footer `BREAKING CHANGE:` | ✅ called out | **minor bump** (your only path to `v0.X+1.0`) |
| Footer `Release-As: 0.X.Y` | overrides version explicitly | Forces release-please to propose the named version |

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
refactor(build): per-arch BPF objects under internal/ebpf/embedded

BREAKING CHANGE: env var PODTRACE_BPF_OBJECT now defaults to a
per-arch path. Users overriding this var must update.
```

The bump rules above apply pre-1.0. After `v1.0.0`, the standard semver
mapping kicks in (`feat:` → minor, `BREAKING CHANGE:` → major). See
[STABILITY.md](STABILITY.md) for the full versioning policy and the
graduation criteria from `v0.x` to `v1.0.0`.

## How releases happen

The release pipeline is fully automated once a release-worthy commit
lands on `main`:

```
1. You merge a PR with a non-hidden commit type (feat:/fix:/refactor:/perf:/security:)
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

- [ ] Commit message follows Conventional Commits (drives release-please)
- [ ] Tests pass: at minimum `make test-unit`; `make chainsaw` for BPF/operator/agent changes
- [ ] Updated relevant docs in `doc/` if you changed user-visible behavior
- [ ] If touching public surface (CRDs, CLI flags, Helm values, env vars), reviewed [STABILITY.md](STABILITY.md) and called out any breaking change in the commit footer
- [ ] If adding a new BPF probe or feature, considered the kernel-version pitfalls documented in [doc/compatibility.md](doc/compatibility.md)

## Where to ask

- **Issues**: [github.com/gma1k/podtrace/issues](https://github.com/gma1k/podtrace/issues) — bugs, feature requests, design discussions
- **Vulnerabilities**: see [SECURITY.md](SECURITY.md) for the private reporting flow
- **General**: open a `[discussion]`-prefixed issue