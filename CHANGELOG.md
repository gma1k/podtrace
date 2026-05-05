# Changelog

All notable changes to podtrace are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
under the rules described in [STABILITY.md](STABILITY.md).

Going forward, releases are managed by [release-please](https://github.com/googleapis/release-please)
based on [Conventional Commits](https://www.conventionalcommits.org/).
Entries below `v0.12.0` were back-filled from git history.

## [0.11.1](https://github.com/gma1k/podtrace/compare/v0.11.0...v0.11.1) (2026-05-05)


### Fixed

* use docker/login-action in chart job so cosign sign can authenticate ([#82](https://github.com/gma1k/podtrace/issues/82)) ([5f1b5b6](https://github.com/gma1k/podtrace/commit/5f1b5b62e9f63b06f02c08d2faa9760b7bf53225))

## [Unreleased]

## [0.11.0] - 2026-04-25

### Added
- Multi-call libfcgi BPF state machine and enriched FastCGI report section ([#75]).

### Changed
- Tightened gosec / CodeQL findings via scoped fs/conv helpers ([#74]).
- envtest CRD path corrected ([#74]).
- Operational chart layer: `TracerConfig`, monitoring templates, narrowed
  agent RBAC, and the CRD documentation set with a Chainsaw e2e suite
  ([#73]).

### Added (operator)
- `PodTraceSession` Job runtime: operator-mounted exporter bundle, CLI
  session sinks, per-session narrow RBAC, kind-smoke verification of the
  full diagnose → Completed path ([#72]).
- Per-node agent DaemonSet runtime with multi-CR merge router,
  exporter-bundle consumption, SSA status writer, Prometheus metrics ([#71]).
- Operator with `TracerConfig`, `PodTrace`, `PodTraceSession` reconcilers,
  exporter-bundle sync, kind e2e smoke ([#70]).
- Initial scaffold: Kubernetes operator with `v1alpha1` CRDs, validating
  webhooks, tracer engine seam, Helm chart ([#69]).

## [0.10.0] - 2026-04-19

### Added
- DataDog and Zipkin trace exporters ([#68]).
- Multi-pod tracing and cross-namespace support ([#63]).

### Changed
- README consolidated into `doc/` ([#68]).
- Multi-pod tracing features restored to README.

### Fixed
- Capitalization of "Datadog" in README.

## [0.9.0] - 2026-02-28

### Added
- Language-runtime adapters: Redis, Memcached, FastCGI, gRPC, Kafka,
  USDT, and PII redaction ([#61]).
- Filesystem path extraction, IPv6 fix, event schema V4, runtime probe
  groups, configurable BPF map sizes, alert thresholds, and
  unlink/rename event types ([#60]).
- Reliability hardening: stack traces, channel-depth metrics, pprof,
  fuzz tests, govulncheck, gosec, security fixes ([#58]).
- Cross-environment portability improvements, expanded test coverage,
  doc improvements ([#56]).

### Changed
- Replaced large `vmlinux.h` fallback with a minimal stub since the
  required types are locally defined or forward-declared in
  `bpf/common.h` ([#59]).

### Fixed
- Cgroup resolution for CRI runtimes ([#57]).
- DaemonSet no-events and systemd cgroup driver issue ([#55]).

## [0.8.0] - 2025-12-17

### Added
- CRI-O support and enhanced diagnostics ([#53]).
- Real-time alerting system with webhook, Slack, and other sinks ([#46]).
- Connection pool monitoring ([#44]).
- Resource limit monitoring for CPU, memory, and I/O ([#42]).

### Changed
- CLI now prints version on `--version` ([#50]).
- CI workflow optimized; test coverage improved; linter errors cleaned;
  alerting config migrated ([#49]).
- Replaced `pathresolver` with kernel path resolution ([#45]).

### Fixed
- Bug fixes and security hardening ([#48]).
- `vmlinux.h` placeholder file ([#47]).
- `bpf_d_path` replaced with inode-based path resolution for
  cross-kernel compatibility ([#41]).

## [0.7.0] - 2025-12-07

### Added
- Distributed tracing support: OTLP, Jaeger, and Splunk exporters ([#40]).
- TLS / SSL handshake tracking ([#39]).
- Kubernetes context enrichment with pod-to-pod tracking and error
  correlation with root-cause analysis ([#38]).
- Multi-architecture support with dynamic library discovery,
  priority-based event sampling, LRU caching, and improved error
  handling ([#35]).
- Structured logging with zap and internal metrics tracking ([#29]).
- Comprehensive test suite ([#25]).
- Issue templates ([#23]).

### Changed
- Codebase reorganized into modular folder structure ([#34]).
- `GenerateReport()` in `diagnose.go` refactored ([#28]).
- Configuration centralized; bug fixes; code-quality improvements ([#27]).

### Fixed
- `runDiagnoseMode` lint issue.
- Code hardening ([#24]).

### Security
- eBPF parser and cgroup filter testing hardened ([#26]).

## [0.6.0] - 2025-12-02

### Added
- Stack traces, lock contention, syscall tracing, network reliability,
  and database query monitoring ([#22]).
- File-path tracking and I/O bandwidth metrics ([#21]).
- UDP/HTTP tracing, OOM-Kill detection ([#18]).
- Remaining feature gaps from initial roadmap closed ([#17]).
- Initial podtrace doc set ([#16]).

### Changed
- Large files split for maintainability ([#19]).

### Fixed
- I/O bandwidth value calculation ([#18]).

### Security
- CLI validation and metrics config hardened ([#20]).
- Security hardening pass ([#15]).

## [0.5.0] - 2025-11-28

### Added
- Metric visualization via Prometheus and Grafana ([#14]).
- Ring buffer, file read operations, IPv6 support, CPU scheduling, and
  DNS tracking ([#13]).

### Changed
- README logo and description updated ([#11]).

## [0.4.0] - 2025-11-23

### Added
- Real-time mode with periodic updates ([#10]).
- CPU usage tracking.

### Fixed
- ShellCheck warnings; CodeQL Go setup in CI ([#9]).

## [0.3.0] - 2025-11-22

### Changed
- Dependencies bumped to latest; GitHub Actions workflows improved ([#7]).

## [0.2.0] - 2025-11-22

### Changed
- Dependency updates: `golang.org/x/oauth2` 0.12.0 → 0.27.0 ([#6]),
  `google.golang.org/protobuf` 1.31.0 → 1.33.0 ([#5]),
  `golang.org/x/net` 0.19.0 → 0.38.0 ([#4]), eBPF and cobra packages
  updated ([#3]).
- `actions/checkout` upgraded v3 → v4.
- `bash-checks` workflow refactored.

### Fixed
- Filesystem-monitoring description in README.

## [0.1.0] - 2025-11-21

### Added
- Initial public release of podtrace.
- Core eBPF-based diagnostic CLI for Kubernetes pods.
- GitHub Actions CI ([#2]).

[Unreleased]: https://github.com/gma1k/podtrace/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/gma1k/podtrace/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/gma1k/podtrace/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/gma1k/podtrace/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/gma1k/podtrace/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/gma1k/podtrace/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/gma1k/podtrace/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/gma1k/podtrace/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/gma1k/podtrace/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/gma1k/podtrace/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/gma1k/podtrace/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/gma1k/podtrace/releases/tag/v0.1.0
