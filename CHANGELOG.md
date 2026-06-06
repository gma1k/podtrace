# Changelog

All notable changes to Podtrace are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
under the rules described in [STABILITY.md](STABILITY.md).

Going forward, releases are managed by [release-please](https://github.com/googleapis/release-please)
based on [Conventional Commits](https://www.conventionalcommits.org/).

## [0.12.6](https://github.com/gma1k/podtrace/compare/v0.12.5...v0.12.6) (2026-06-06)


### Features

* add libc-independent DNS packet capture with v4/v6 parity ([#191](https://github.com/gma1k/podtrace/issues/191)) ([0846b77](https://github.com/gma1k/podtrace/commit/0846b771392ae230c60b1aa77f69d6c347d87915))


### Bug Fixes

* quieter startup warnings and workstation-side event correlation ([#190](https://github.com/gma1k/podtrace/issues/190)) ([8c23bd8](https://github.com/gma1k/podtrace/commit/8c23bd809fbe9ab21f678e009b99d822f20f81b9))
* timeline bucket overlap ([#186](https://github.com/gma1k/podtrace/issues/186)) and OLM workflow-scope push ([#188](https://github.com/gma1k/podtrace/issues/188)) ([50bcf50](https://github.com/gma1k/podtrace/commit/50bcf50126849a3fa3036360e4e91c7b54230287))

## [0.12.5](https://github.com/gma1k/podtrace/compare/v0.12.4...v0.12.5) (2026-06-05)


### Features

* add --app/--label application targeting (ephemeral + managed) ([#182](https://github.com/gma1k/podtrace/issues/182)) ([73aa96e](https://github.com/gma1k/podtrace/commit/73aa96e052f283474495054a7864721d04b31b56))


### Bug Fixes

* default namespace to current kubeconfig context ([#185](https://github.com/gma1k/podtrace/issues/185)) ([efa6f3a](https://github.com/gma1k/podtrace/commit/efa6f3a95bada8a89dea8b2c2af5c3897905d4f0))
* derive docker GO_VERSION from go.mod with GOTOOLCHAIN=auto ([#180](https://github.com/gma1k/podtrace/issues/180)) ([e5da3cd](https://github.com/gma1k/podtrace/commit/e5da3cd17d3740aa84c678840d191e29a24d0b0f))


### Maintenance

* **deps:** update docker/setup-qemu-action action to v4.1.0 ([#175](https://github.com/gma1k/podtrace/issues/175)) ([9009a71](https://github.com/gma1k/podtrace/commit/9009a7167bfb02238538d28ea859805fa44c53bb))
* **deps:** update github actions ([#177](https://github.com/gma1k/podtrace/issues/177)) ([b8df373](https://github.com/gma1k/podtrace/commit/b8df3735285d3e2ec9ffeac2ef0fa135752638c5))
* **deps:** update github actions to v4.36.2 ([#183](https://github.com/gma1k/podtrace/issues/183)) ([118d6d2](https://github.com/gma1k/podtrace/commit/118d6d21984bb01e2335e2a6039b448a79093c01))
* **deps:** update go modules (non-major) ([#174](https://github.com/gma1k/podtrace/issues/174)) ([3d96d9d](https://github.com/gma1k/podtrace/commit/3d96d9d5f7d1251610435d1aaca0f51818a35be8))
* **deps:** update go modules (non-major) ([#179](https://github.com/gma1k/podtrace/issues/179)) ([0f95880](https://github.com/gma1k/podtrace/commit/0f958802b26c9fbe7d5d95963346ecf3594df24f))
* **deps:** update go modules (non-major) ([#184](https://github.com/gma1k/podtrace/issues/184)) ([2ca4fea](https://github.com/gma1k/podtrace/commit/2ca4fea1000453916085def21f93b49dfef0ab88))
* **deps:** update go modules (non-major) to v0.283.0 ([#178](https://github.com/gma1k/podtrace/issues/178)) ([76570d4](https://github.com/gma1k/podtrace/commit/76570d47a64329890089f68b7a8ac814f07f4e55))

## [0.12.4](https://github.com/gma1k/podtrace/compare/v0.12.3...v0.12.4) (2026-05-29)


### Bug Fixes

* **cli:** always surface spawn-pod failure cause instead of bare kubelet error ([#172](https://github.com/gma1k/podtrace/issues/172)) ([fbc061e](https://github.com/gma1k/podtrace/commit/fbc061efc4a39d22521105eaeb526fb03fc9ad32))

## [0.12.3](https://github.com/gma1k/podtrace/compare/v0.12.2...v0.12.3) (2026-05-27)


### Bug Fixes

* **cli:** reap spawn pod orphans by owner-pid liveness ([#169](https://github.com/gma1k/podtrace/issues/169)) ([e5b8c4b](https://github.com/gma1k/podtrace/commit/e5b8c4b90208786d53df073b06ad14e5ef388a8f))
* **cli:** spawn pod debug UX and host-aware Lockdown LSM detection ([#167](https://github.com/gma1k/podtrace/issues/167)) ([037c0e4](https://github.com/gma1k/podtrace/commit/037c0e4573ad77893b54f3beba91e6a0ebdd03d2))


### Maintenance

* **release:** align chart version with appVersion via helm extra-file ([#170](https://github.com/gma1k/podtrace/issues/170)) ([7a6c716](https://github.com/gma1k/podtrace/commit/7a6c71627a256c0dcc3a0055b961fcc7685f6f2a))
* **release:** align chart version with appVersion via yaml updaters ([#171](https://github.com/gma1k/podtrace/issues/171)) ([3caf65d](https://github.com/gma1k/podtrace/commit/3caf65d15e263c48a22d837d2fac7e18a1d7afbb))

## [0.12.2](https://github.com/gma1k/podtrace/compare/v0.12.1...v0.12.2) (2026-05-26)


### Features

* **cli:** improve spawn pod debug UX and detect kernel Lockdown ([#161](https://github.com/gma1k/podtrace/issues/161)) ([3dd672b](https://github.com/gma1k/podtrace/commit/3dd672b715cc9ed869dadb3ba2ef277f8e5ca8d4))


### Bug Fixes

* full BPF verifier log on failure + spawn pod argv strip ([#166](https://github.com/gma1k/podtrace/issues/166)) ([93978d8](https://github.com/gma1k/podtrace/commit/93978d8ec8a2ff6ed4828ecbe7310c80000a44ea))


### CI

* **release:** use OPERATORHUB_PAT for cross-fork OLM submission ([#164](https://github.com/gma1k/podtrace/issues/164)) ([b485016](https://github.com/gma1k/podtrace/commit/b485016406791502487d7714890d20c8fd0b8b0f))


### Maintenance

* **release:** explicit release bumps via release-as in config ([#163](https://github.com/gma1k/podtrace/issues/163)) ([be53d14](https://github.com/gma1k/podtrace/commit/be53d141db67e04010700b46accff9c699c1d4fa))

## [0.12.1](https://github.com/gma1k/podtrace/compare/v0.12.0...v0.12.1) (2026-05-24)


### Bug Fixes

* spawn image tag v-prefix mismatch and OLM bundle push auth ([#158](https://github.com/gma1k/podtrace/issues/158)) ([9cd2f65](https://github.com/gma1k/podtrace/commit/9cd2f6531bbefb36536d237b7dcf814f405643a0))

## [0.12.0](https://github.com/gma1k/podtrace/compare/v0.11.0...v0.12.0) (2026-05-24)


### Features

* add PodTraceSchedule CRD, rename PodTraceSession to `.status.state`, and harden operator/CLI reconcile and error paths ([#118](https://github.com/gma1k/podtrace/issues/118)) ([97f7407](https://github.com/gma1k/podtrace/commit/97f74073ed8ec355f6647ad017c11ee4f6ce67db))
* **agent:** add --backend flag, backend_degraded metric, and typed startup-error classes for explicit production safety and degraded-mode observability ([#122](https://github.com/gma1k/podtrace/issues/122)) ([170de33](https://github.com/gma1k/podtrace/commit/170de33688d45b85af090a8487025b86e3a539e2))
* **agent:** add Jaeger/DataDog/Splunk exporters, version bundles, manage CRDs via Helm hooks ([#113](https://github.com/gma1k/podtrace/issues/113)) ([dd6a1aa](https://github.com/gma1k/podtrace/commit/dd6a1aae108a6c2a427a5c68483187df1003d582))
* **agent:** attach k8s pod and workload context to exported spans ([#140](https://github.com/gma1k/podtrace/issues/140)) ([d357ab0](https://github.com/gma1k/podtrace/commit/d357ab02348565ea895e1aca706b74f60bf33d37))
* **agent:** stamp nodeStatus.reason and per-program, exporter init metrics ([#145](https://github.com/gma1k/podtrace/issues/145)) ([b31df33](https://github.com/gma1k/podtrace/commit/b31df33d5414c667b57d04bb9a31a2466dd7d317))
* **agent:** surface per-CR failures as Degraded condition with cause on NodeStatus.Message ([#109](https://github.com/gma1k/podtrace/issues/109)) ([bd0322b](https://github.com/gma1k/podtrace/commit/bd0322bdd97229a8d5fd7b1ff55c3bbd24f9a504))
* **agent:** wire podtrace policy, filters, sample, thresholds end-to-end ([#142](https://github.com/gma1k/podtrace/issues/142)) ([15e6800](https://github.com/gma1k/podtrace/commit/15e680007a1b519c7e7bb5e8e6e364493cfd62f0))
* **cli:** add Make-based release pipeline for signed multi-platform tarballs ([#87](https://github.com/gma1k/podtrace/issues/87)) ([4fbd4b9](https://github.com/gma1k/podtrace/commit/4fbd4b9ea0fabf48aafb6ec3ca1cfacf03a11c59))
* **cli:** krew compatibility, auth plugins import and kubectl-aware Use string ([#95](https://github.com/gma1k/podtrace/issues/95)) ([e989941](https://github.com/gma1k/podtrace/commit/e9899417add0ad6685cb86996de5b535631665c4))
* cross-namespace PodTrace targeting via spec.namespaceSelector and chart namespace-bootstrap hardening ([#115](https://github.com/gma1k/podtrace/issues/115)) ([7d70f3f](https://github.com/gma1k/podtrace/commit/7d70f3ff9bed2f7a8bb58a665852e6fb14cc46ff))
* **operator:** ExporterConfig status reconciler, changelog and CI hygiene ([#117](https://github.com/gma1k/podtrace/issues/117)) ([c70a710](https://github.com/gma1k/podtrace/commit/c70a71005646db953cc240ee4504df17bcbd3d27))
* **release:** add OperatorHub.io OLM bundle pipeline ([#100](https://github.com/gma1k/podtrace/issues/100)) ([7f08a63](https://github.com/gma1k/podtrace/commit/7f08a6316514d6c280b0414f400b2478d19a0af7))
* **reports:** upload session reports to S3/GCS/Azure object stores, fix agent BPF wiring, harden chart fresh-install path ([#116](https://github.com/gma1k/podtrace/issues/116)) ([ec6e335](https://github.com/gma1k/podtrace/commit/ec6e3354dae7bc1ccf88a07400e451e313359fda))
* rolling-window error_rate detector and selective probe attach ([#143](https://github.com/gma1k/podtrace/issues/143)) ([4624181](https://github.com/gma1k/podtrace/commit/46241815c58b7039a19fbe64ff597ad427d204ab))
* surface objectStore upload reason, attempts, and retry logs ([#144](https://github.com/gma1k/podtrace/issues/144)) ([9f4937e](https://github.com/gma1k/podtrace/commit/9f4937ee2a14ad8de0c3bf32a5ee83f0f49e6643))
* **tracer:** snapshot-replace cgroup lifecycle with atomic filter set prunes stale attachments on pod churn and closes a kernel-cgroup-ID-recycling correctness bug ([#124](https://github.com/gma1k/podtrace/issues/124)) ([97690f4](https://github.com/gma1k/podtrace/commit/97690f4545d9bcb85c2a14874f883321ca143a4e))


### Bug Fixes

* **build:** cross-compile to darwin via build-tagged Prctl + fail-fast release loop ([#93](https://github.com/gma1k/podtrace/issues/93)) ([16cf498](https://github.com/gma1k/podtrace/commit/16cf498cd48019a2821c8b221ba10e38937ca213))
* **build:** wire ldflags version injection through config and Makefile, add community files ([#90](https://github.com/gma1k/podtrace/issues/90)) ([c33e451](https://github.com/gma1k/podtrace/commit/c33e451c3fcb3bb9385fde2aca53ad363f683721))
* **ci:** route Release-As workflow through a PR to respect branch protection ([#151](https://github.com/gma1k/podtrace/issues/151)) ([e620914](https://github.com/gma1k/podtrace/commit/e6209142aec9da5564aad67a853c5f76eb74914e))
* **cli:** always render help as "podtrace" regardless of invocation path ([#97](https://github.com/gma1k/podtrace/issues/97)) ([25b08a1](https://github.com/gma1k/podtrace/commit/25b08a103e8280c9730b03d929c14d1e655b9bfb))
* **cli:** run eBPF on target node via spawn pod ([#150](https://github.com/gma1k/podtrace/issues/150)) ([edff9a4](https://github.com/gma1k/podtrace/commit/edff9a4fff11533a8fab9d288c2dc58c22fe0e41))
* **olm:** point bundle builder at templates/crds/ and register PodTraceSchedule in the CSV ([#119](https://github.com/gma1k/podtrace/issues/119)) ([4b36ffa](https://github.com/gma1k/podtrace/commit/4b36ffa94adb7e8867ce0ef938e4991208f5c375))
* **release:** correct .krew.yaml indentation + bump docker/login-action to v4.1.0 ([#102](https://github.com/gma1k/podtrace/issues/102)) ([ee7da68](https://github.com/gma1k/podtrace/commit/ee7da6806629a1ea68adc56105765eec27dc5228))


### Refactors

* per-arch BPF objects under internal/ebpf/embedded and sync docs ([#84](https://github.com/gma1k/podtrace/issues/84)) ([470ee82](https://github.com/gma1k/podtrace/commit/470ee82c8fc8eb13ff015dabb3030f49123c572e))


### Documentation

* add Artifact Hub badge to README ([#134](https://github.com/gma1k/podtrace/issues/134)) ([5a9687f](https://github.com/gma1k/podtrace/commit/5a9687fd01100c34c22968d75f2dadef147daf12))
* add OperatorHub.io install path to README + installation + openshift ([#108](https://github.com/gma1k/podtrace/issues/108)) ([c77e9ad](https://github.com/gma1k/podtrace/commit/c77e9ad2e0bdb2e3737b57a2bd57e9664a84c10c))
* **charts:** add chart README rendered on Artifact Hub ([#129](https://github.com/gma1k/podtrace/issues/129)) ([c39fca3](https://github.com/gma1k/podtrace/commit/c39fca306e9f8ff29a262799e5cc37f9a2233da6))
* **charts:** tighten chart description and add PodTraceSchedule to CRD list ([#126](https://github.com/gma1k/podtrace/issues/126)) ([d83da74](https://github.com/gma1k/podtrace/commit/d83da7498d018a1b7961e826637d41b853598e63))
* use sudo for /usr/local/bin extract in CLI install snippets ([#92](https://github.com/gma1k/podtrace/issues/92)) ([e0c9f44](https://github.com/gma1k/podtrace/commit/e0c9f44339c6dad9faa73fb0e85b93e56a54c973))


### Tests

* enforce OTLP-only agent exporter contract with golden tests ([#139](https://github.com/gma1k/podtrace/issues/139)) ([6f452a2](https://github.com/gma1k/podtrace/commit/6f452a2712e12e03b6c7f1d746ea30ef144d6862))


### CI

* add release-notes enrichment, PR labeller, and Release-As trigger ([#121](https://github.com/gma1k/podtrace/issues/121)) ([d974e09](https://github.com/gma1k/podtrace/commit/d974e099cf8ebc246453f4e738b02fe7309b1e2c))
* auto-create conventional-commit labels in label-conventional-prs workflow ([#123](https://github.com/gma1k/podtrace/issues/123)) ([e7af61b](https://github.com/gma1k/podtrace/commit/e7af61ba636ad1a42adb0fba9204942164023ed4))
* migrate CLI checksum signing to cosign v3 keyless bundle format to fix release workflow failures ([#89](https://github.com/gma1k/podtrace/issues/89)) ([09a5226](https://github.com/gma1k/podtrace/commit/09a522632ee85ac52f0efa689f66318c66393f83))
* **olm:** bot commits cannot be GPG-signed ([#112](https://github.com/gma1k/podtrace/issues/112)) ([d29bdff](https://github.com/gma1k/podtrace/commit/d29bdff41c0a7caea495d19a9663d06216184d77))
* **olm:** make upstream remote add idempotent against gh repo clone ([#111](https://github.com/gma1k/podtrace/issues/111)) ([d7e665e](https://github.com/gma1k/podtrace/commit/d7e665e1e7c548aa8db38b3f2e02b3bf95ada22f))
* **refactor:** drop redundant push-to-main triggers ([#107](https://github.com/gma1k/podtrace/issues/107)) ([55d1eeb](https://github.com/gma1k/podtrace/commit/55d1eeb36f76d164208fe7859d75ebb561c505cb))
* **refactor:** tighten triggers, extract BPF toolchain action, pin all third-party actions to SHA ([#106](https://github.com/gma1k/podtrace/issues/106)) ([958fac4](https://github.com/gma1k/podtrace/commit/958fac4d29e28f3ba48e7d180f13966d8dc03811))
* **release:** auto-submit OLM bundle to community-operators per tag ([#105](https://github.com/gma1k/podtrace/issues/105)) ([29053eb](https://github.com/gma1k/podtrace/commit/29053eb22dc9c51e461990867ea61567cc216d55))
* **release:** re-push Artifact Hub verification artifact on every release ([#127](https://github.com/gma1k/podtrace/issues/127)) ([d668e73](https://github.com/gma1k/podtrace/commit/d668e734bfdc64cd335088add214c78db7a810dc))
* **release:** wire krew-release-bot for automated krew-index PRs ([#99](https://github.com/gma1k/podtrace/issues/99)) ([7ce6e25](https://github.com/gma1k/podtrace/commit/7ce6e25a06a427f8d9b3cdeb92a75bb096138c91))


### Maintenance

* announce 0.12.0 ([#152](https://github.com/gma1k/podtrace/issues/152)) ([4d67a5d](https://github.com/gma1k/podtrace/commit/4d67a5d320f5dfbc41652e95980e52437ca78197))
* bump k8s.io packages to v0.34.8 and add FOSSA license badges ([#137](https://github.com/gma1k/podtrace/issues/137)) ([17d46c8](https://github.com/gma1k/podtrace/commit/17d46c868df04eb715d4c125e7f47368af634cd2))
* chart NOTES URL, release tags, and PAT for release-please ([#83](https://github.com/gma1k/podtrace/issues/83)) ([114eeeb](https://github.com/gma1k/podtrace/commit/114eeeba8010eef61546546d88bc5c6e7e59739d))
* **charts:** add artifacthub-repo.yml for Verified Publisher ([#125](https://github.com/gma1k/podtrace/issues/125)) ([0dda799](https://github.com/gma1k/podtrace/commit/0dda79915a3b63e6e37b005b47acfc2b4a6088e1))
* **charts:** add values.schema.json ([#132](https://github.com/gma1k/podtrace/issues/132)) ([3ffb92b](https://github.com/gma1k/podtrace/commit/3ffb92b7af8f807998179911db04540d7206530f))
* **ci:** release-please bumps patch on feat: while pre-1.0 ([#86](https://github.com/gma1k/podtrace/issues/86)) ([9dd5d41](https://github.com/gma1k/podtrace/commit/9dd5d416af9c2e0784a01696842f0239e07ec3b8))
* **config:** migrate config .github/renovate.json ([#146](https://github.com/gma1k/podtrace/issues/146)) ([3a0a18d](https://github.com/gma1k/podtrace/commit/3a0a18ded774e7c7641880e48a87421332ed3205))
* **deps:** update module sigs.k8s.io/structured-merge-diff/v6 to v6.4.0 ([#148](https://github.com/gma1k/podtrace/issues/148)) ([8ff3976](https://github.com/gma1k/podtrace/commit/8ff39765533a58f1a91bb7a6fa4f4e92f81e5163))
* **main:** release 0.11.1 ([#85](https://github.com/gma1k/podtrace/issues/85)) ([cd7f993](https://github.com/gma1k/podtrace/commit/cd7f9933e5df707c9a547b7c0878719a44ce6335))
* **main:** release 0.11.2 ([#88](https://github.com/gma1k/podtrace/issues/88)) ([222773c](https://github.com/gma1k/podtrace/commit/222773c4413f231dfa2e59c65c989369bf1acf28))
* **main:** release 0.11.3 ([#91](https://github.com/gma1k/podtrace/issues/91)) ([11e7c2f](https://github.com/gma1k/podtrace/commit/11e7c2f74ec315121da2e1584cdaaa7d2f9e2568))
* **main:** release 0.11.4 ([#94](https://github.com/gma1k/podtrace/issues/94)) ([126b14a](https://github.com/gma1k/podtrace/commit/126b14acc2b506210bb341e80c76ec2fc9f8f3b8))
* **main:** release 0.11.5 ([#96](https://github.com/gma1k/podtrace/issues/96)) ([9672c56](https://github.com/gma1k/podtrace/commit/9672c56a40662c0db3d1ef146ff634c7e4008bff))
* **main:** release 0.11.6 ([#98](https://github.com/gma1k/podtrace/issues/98)) ([ee750a3](https://github.com/gma1k/podtrace/commit/ee750a3e6952e95b41a9ec8fa820d61f9360e87f))
* **main:** release 0.11.7 ([#101](https://github.com/gma1k/podtrace/issues/101)) ([0f7492b](https://github.com/gma1k/podtrace/commit/0f7492b6d5398130cc329af47b61572786c1bbfb))
* **main:** release 0.11.8 ([#103](https://github.com/gma1k/podtrace/issues/103)) ([67229ce](https://github.com/gma1k/podtrace/commit/67229ceef0760457ca0d8092254f5cc867a557cb))
* **main:** release 0.11.9 ([#110](https://github.com/gma1k/podtrace/issues/110)) ([9e51011](https://github.com/gma1k/podtrace/commit/9e510110f074551aff26d753cd2ccce8a35d0bb4))
* **release:** release 0.11.10 ([#114](https://github.com/gma1k/podtrace/issues/114)) ([3a0a5cf](https://github.com/gma1k/podtrace/commit/3a0a5cf0d938ed5d3f603080fd2685dedf4ba454))
* **release:** release 0.11.11 ([#120](https://github.com/gma1k/podtrace/issues/120)) ([7650709](https://github.com/gma1k/podtrace/commit/765070996080388ac4ba4a52b3fea7a7d1a12c4a))
* **release:** use standard semver bumps for pre-v1.0 ([#155](https://github.com/gma1k/podtrace/issues/155)) ([99f70a1](https://github.com/gma1k/podtrace/commit/99f70a1c0cd74e0d08f06825d7a2a64bb5be77c4))

## [0.11.11](https://github.com/gma1k/podtrace/compare/v0.11.10...v0.11.11) (2026-05-18)


### Features

* **agent:** add --backend flag, backend_degraded metric, and typed startup-error classes for explicit production safety and degraded-mode observability ([#122](https://github.com/gma1k/podtrace/issues/122)) ([170de33](https://github.com/gma1k/podtrace/commit/170de33688d45b85af090a8487025b86e3a539e2))
* **tracer:** snapshot-replace cgroup lifecycle with atomic filter set prunes stale attachments on pod churn and closes a kernel-cgroup-ID-recycling correctness bug ([#124](https://github.com/gma1k/podtrace/issues/124)) ([97690f4](https://github.com/gma1k/podtrace/commit/97690f4545d9bcb85c2a14874f883321ca143a4e))


### Bug Fixes

* **olm:** point bundle builder at templates/crds/ and register PodTraceSchedule in the CSV ([#119](https://github.com/gma1k/podtrace/issues/119)) ([4b36ffa](https://github.com/gma1k/podtrace/commit/4b36ffa94adb7e8867ce0ef938e4991208f5c375))

## [0.11.10](https://github.com/gma1k/podtrace/compare/v0.11.9...v0.11.10) (2026-05-15)


### Added

* add PodTraceSchedule CRD, rename PodTraceSession to `.status.state`, and harden operator/CLI reconcile and error paths ([#118](https://github.com/gma1k/podtrace/issues/118)) ([97f7407](https://github.com/gma1k/podtrace/commit/97f74073ed8ec355f6647ad017c11ee4f6ce67db))
* **agent:** add Jaeger/DataDog/Splunk exporters, version bundles, manage CRDs via Helm hooks ([#113](https://github.com/gma1k/podtrace/issues/113)) ([dd6a1aa](https://github.com/gma1k/podtrace/commit/dd6a1aae108a6c2a427a5c68483187df1003d582))
* cross-namespace PodTrace targeting via spec.namespaceSelector and chart namespace-bootstrap hardening ([#115](https://github.com/gma1k/podtrace/issues/115)) ([7d70f3f](https://github.com/gma1k/podtrace/commit/7d70f3ff9bed2f7a8bb58a665852e6fb14cc46ff))
* **operator:** ExporterConfig status reconciler, changelog and CI hygiene ([#117](https://github.com/gma1k/podtrace/issues/117)) ([c70a710](https://github.com/gma1k/podtrace/commit/c70a71005646db953cc240ee4504df17bcbd3d27))
* **reports:** upload session reports to S3/GCS/Azure object stores, fix agent BPF wiring, harden chart fresh-install path ([#116](https://github.com/gma1k/podtrace/issues/116)) ([ec6e335](https://github.com/gma1k/podtrace/commit/ec6e3354dae7bc1ccf88a07400e451e313359fda))

## [0.11.9](https://github.com/gma1k/podtrace/compare/v0.11.8...v0.11.9) (2026-05-11)


### Added

* **agent:** surface per-CR failures as Degraded condition with cause on NodeStatus.Message ([#109](https://github.com/gma1k/podtrace/issues/109)) ([bd0322b](https://github.com/gma1k/podtrace/commit/bd0322bdd97229a8d5fd7b1ff55c3bbd24f9a504))

## [0.11.8](https://github.com/gma1k/podtrace/compare/v0.11.7...v0.11.8) (2026-05-09)


### Fixed

* **release:** correct .krew.yaml indentation + bump docker/login-action to v4.1.0 ([#102](https://github.com/gma1k/podtrace/issues/102)) ([ee7da68](https://github.com/gma1k/podtrace/commit/ee7da6806629a1ea68adc56105765eec27dc5228))

## [0.11.7](https://github.com/gma1k/podtrace/compare/v0.11.6...v0.11.7) (2026-05-09)


### Added

* **release:** add OperatorHub.io OLM bundle pipeline ([#100](https://github.com/gma1k/podtrace/issues/100)) ([7f08a63](https://github.com/gma1k/podtrace/commit/7f08a6316514d6c280b0414f400b2478d19a0af7))

## [0.11.6](https://github.com/gma1k/podtrace/compare/v0.11.5...v0.11.6) (2026-05-08)


### Fixed

* **cli:** always render help as "podtrace" regardless of invocation path ([#97](https://github.com/gma1k/podtrace/issues/97)) ([25b08a1](https://github.com/gma1k/podtrace/commit/25b08a103e8280c9730b03d929c14d1e655b9bfb))

## [0.11.5](https://github.com/gma1k/podtrace/compare/v0.11.4...v0.11.5) (2026-05-08)


### Added

* **cli:** krew compatibility, auth plugins import and kubectl-aware Use string ([#95](https://github.com/gma1k/podtrace/issues/95)) ([e989941](https://github.com/gma1k/podtrace/commit/e9899417add0ad6685cb86996de5b535631665c4))

## [0.11.4](https://github.com/gma1k/podtrace/compare/v0.11.3...v0.11.4) (2026-05-08)


### Fixed

* **build:** cross-compile to darwin via build-tagged Prctl + fail-fast release loop ([#93](https://github.com/gma1k/podtrace/issues/93)) ([16cf498](https://github.com/gma1k/podtrace/commit/16cf498cd48019a2821c8b221ba10e38937ca213))

## [0.11.3](https://github.com/gma1k/podtrace/compare/v0.11.2...v0.11.3) (2026-05-07)


### Fixed

* **build:** wire ldflags version injection through config and Makefile, add community files ([#90](https://github.com/gma1k/podtrace/issues/90)) ([c33e451](https://github.com/gma1k/podtrace/commit/c33e451c3fcb3bb9385fde2aca53ad363f683721))

## [0.11.2](https://github.com/gma1k/podtrace/compare/v0.11.1...v0.11.2) (2026-05-06)


### Added

* **cli:** add Make-based release pipeline for signed multi-platform tarballs ([#87](https://github.com/gma1k/podtrace/issues/87)) ([4fbd4b9](https://github.com/gma1k/podtrace/commit/4fbd4b9ea0fabf48aafb6ec3ca1cfacf03a11c59))

## [0.11.1](https://github.com/gma1k/podtrace/compare/v0.11.0...v0.11.1) (2026-05-06)


### Changed

* per-arch BPF objects under internal/ebpf/embedded and sync docs ([#84](https://github.com/gma1k/podtrace/issues/84)) ([470ee82](https://github.com/gma1k/podtrace/commit/470ee82c8fc8eb13ff015dabb3030f49123c572e))

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
- README consolidated into `docs/` ([#68]).
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
