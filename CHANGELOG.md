# Changelog

All notable changes to Podtrace are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
under the rules described in [STABILITY.md](STABILITY.md).

Going forward, releases are managed by [release-please](https://github.com/googleapis/release-please)
based on [Conventional Commits](https://www.conventionalcommits.org/).

## [0.13.7](https://github.com/gma1k/podtrace/compare/v0.13.6...v0.13.7) (2026-07-05)


### Features

* decode HTTP/2 :path mid-stream and stop idle-agent whole-node OOM ([#283](https://github.com/gma1k/podtrace/issues/283)) ([1f9e190](https://github.com/gma1k/podtrace/commit/1f9e190894101d46b4978edf96f5fad48f03e2ca))
* decode inbound HTTP/3 adapter headers and probe quiche crate ([#284](https://github.com/gma1k/podtrace/issues/284)) ([0ba9a08](https://github.com/gma1k/podtrace/commit/0ba9a08ffc375f61819a061c15b8c58eaf6c4885))
* harden HTTP/3 tracing with peer fusion, QUIC v2, and adapters ([#280](https://github.com/gma1k/podtrace/issues/280)) ([d5190bc](https://github.com/gma1k/podtrace/commit/d5190bc16847f3a3166149a448de29f1eea9c232))


### Maintenance

* **deps:** update docker/login-action action to v4.4.0 ([#282](https://github.com/gma1k/podtrace/issues/282)) ([b85af11](https://github.com/gma1k/podtrace/commit/b85af113108e98b0543ef68551d685b9fcf8f53e))

## [0.13.6](https://github.com/gma1k/podtrace/compare/v0.13.5...v0.13.6) (2026-07-02)


### Features

* capture grpc-go and netty-tcnative HTTP/2 L7 over TLS ([#272](https://github.com/gma1k/podtrace/issues/272)) ([9a4db41](https://github.com/gma1k/podtrace/commit/9a4db411a14dce4266234ae68e11f049b068147e))
* capture inbound HTTP/1.x server-side via connection keying ([#269](https://github.com/gma1k/podtrace/issues/269)) ([4d908d5](https://github.com/gma1k/podtrace/commit/4d908d5cfe063db70f9f5f8a1fa2effcbb28a867))
* capture rustls (Rust) TLS L7 via plaintext uprobes ([#276](https://github.com/gma1k/podtrace/issues/276)) ([40eeb1c](https://github.com/gma1k/podtrace/commit/40eeb1c51197442d26c12d0144f0d3ff7e2cf779))
* harden HTTP/3 L7 with DWARF offsets and traceparent capture ([#267](https://github.com/gma1k/podtrace/issues/267)) ([7b982d8](https://github.com/gma1k/podtrace/commit/7b982d85a37ebb42be58ee6490841db28d413555))
* resolve rustls symbols under v0 mangling and via debug files ([#278](https://github.com/gma1k/podtrace/issues/278)) ([bde6ae8](https://github.com/gma1k/podtrace/commit/bde6ae82339e745ac57159e98929e27c1645d1bd))


### Bug Fixes

* reject TLS records in h2c frame detection to drop ciphertext noise ([#277](https://github.com/gma1k/podtrace/issues/277)) ([93c58de](https://github.com/gma1k/podtrace/commit/93c58de370ef2351202c6332776811c009f58170))


### Tests

* cover quicinitial QUIC Initial parsing and agent copy-fail alert ([#279](https://github.com/gma1k/podtrace/issues/279)) ([f573d16](https://github.com/gma1k/podtrace/commit/f573d163dd1bb6f5e19a5843dfd6aad0cf622ad5))


### Maintenance

* **deps:** update github actions ([#273](https://github.com/gma1k/podtrace/issues/273)) ([864585c](https://github.com/gma1k/podtrace/commit/864585cdbf4ba6ace0a70eee79b55bde985d2383))
* **deps:** update github actions ([#275](https://github.com/gma1k/podtrace/issues/275)) ([025479f](https://github.com/gma1k/podtrace/commit/025479fe3e507a4cf807111cd2d94f9c144c70f4))
* **deps:** update go modules (non-major) ([#274](https://github.com/gma1k/podtrace/issues/274)) ([58f6785](https://github.com/gma1k/podtrace/commit/58f6785a43215f32de9e0a60d106823d9690801c))
* **deps:** update module google.golang.org/api to v0.287.0 ([#271](https://github.com/gma1k/podtrace/issues/271)) ([4966153](https://github.com/gma1k/podtrace/commit/4966153dc50f3a09b07082048e8a0a12c5388ffb))
* **deps:** update module google.golang.org/grpc to v1.82.0 ([#270](https://github.com/gma1k/podtrace/issues/270)) ([2383ea3](https://github.com/gma1k/podtrace/commit/2383ea34a1d24825c8b4e675d334323af0252030))

## [0.13.5](https://github.com/gma1k/podtrace/compare/v0.13.4...v0.13.5) (2026-06-29)


### Features

* attach TLS uprobes by offset via build-id debug info ([#261](https://github.com/gma1k/podtrace/issues/261)) ([9381c7d](https://github.com/gma1k/podtrace/commit/9381c7d77b97f1482e29b220d0249749acc8544b))
* capture HTTP/3 (QUIC) connections and SNI from the Initial packet ([#263](https://github.com/gma1k/podtrace/issues/263)) ([a535199](https://github.com/gma1k/podtrace/commit/a535199a9cb87d5d4e3273c2d279b3cae1ab4b1f))
* capture Node.js HTTPS h1 + h2 over TLS, client and server ([#259](https://github.com/gma1k/podtrace/issues/259)) ([90b03f1](https://github.com/gma1k/podtrace/commit/90b03f1d67756ae887d34150b34644e83e58979a))
* capture TLS L7 by resolving SSL symbols from .symtab ([#260](https://github.com/gma1k/podtrace/issues/260)) ([cc43ec9](https://github.com/gma1k/podtrace/commit/cc43ec9a1f77fdba22d19d4dc80eb058bd481b4c))
* decode HTTP/3 (QUIC) L7 requests and responses for quic-go ([#265](https://github.com/gma1k/podtrace/issues/265)) ([e801bc3](https://github.com/gma1k/podtrace/commit/e801bc34dd76bde0d0ce05782542d54a1d1f0cce))
* fuse L4 peer 4-tuple onto L7 events ([#262](https://github.com/gma1k/podtrace/issues/262)) ([e715fa7](https://github.com/gma1k/podtrace/commit/e715fa7231898825f3cb692327fe913adaf83783))


### Bug Fixes

* harden HTTP/2 userspace decode egress chunking, Go reads, buffer ([#257](https://github.com/gma1k/podtrace/issues/257)) ([f99c3ce](https://github.com/gma1k/podtrace/commit/f99c3cec3510a16bd35d89c4d803d7fb7f4e1312))


### Maintenance

* **deps:** update go modules (non-major) ([#266](https://github.com/gma1k/podtrace/issues/266)) ([506fd95](https://github.com/gma1k/podtrace/commit/506fd95811ed26dd77b95f13b8212d9ddd69549d))
* **deps:** update golangci/golangci-lint-action action to v9.3.0 ([#264](https://github.com/gma1k/podtrace/issues/264)) ([c2921d1](https://github.com/gma1k/podtrace/commit/c2921d1cedc814d684c89e17d845e77085fb1282))

## [0.13.4](https://github.com/gma1k/podtrace/compare/v0.13.3...v0.13.4) (2026-06-27)


### Features

* capture HTTP/2 (h2c) and Go crypto/tls L7 endpoints ([#253](https://github.com/gma1k/podtrace/issues/253)) ([323e34a](https://github.com/gma1k/podtrace/commit/323e34ae8f3717d17eb4f98a310f5d87b8d631c8))
* capture HTTPS endpoints via SSL_read/SSL_write uprobes ([#251](https://github.com/gma1k/podtrace/issues/251)) ([cd11ea7](https://github.com/gma1k/podtrace/commit/cd11ea76bf7d71911f2d6c6deb8c31a63c6e8b5a))
* decode HTTP/2 HPACK in userspace, deleting the in-kernel decoder ([#255](https://github.com/gma1k/podtrace/issues/255)) ([4efb74d](https://github.com/gma1k/podtrace/commit/4efb74d2696b64a1187383338b9d7aeeeea4b2a2))
* harden Go crypto/tls tracing (stripped binaries, arm64) ([#254](https://github.com/gma1k/podtrace/issues/254)) ([bc05aa7](https://github.com/gma1k/podtrace/commit/bc05aa7e92cd8c3eacc7a6d73a396b5e023ef376))
* stitch eBPF kernel spans into the apps OpenTelemetry trace ([#249](https://github.com/gma1k/podtrace/issues/249)) ([b7f5bee](https://github.com/gma1k/podtrace/commit/b7f5beef917ecacc86b6ad46f667cfa0876d2939))
* trace HTTP/1.x endpoints from sockets with zero instrumentation ([#248](https://github.com/gma1k/podtrace/issues/248)) ([831e57d](https://github.com/gma1k/podtrace/commit/831e57dee156f01816cd6d199a8c145a36f0f084))


### Maintenance

* **deps:** update github actions ([#246](https://github.com/gma1k/podtrace/issues/246)) ([ac65cd2](https://github.com/gma1k/podtrace/commit/ac65cd2b5c312e3bc87afed9d4a456c9b7be9797))
* **deps:** update module cloud.google.com/go/storage to v1.63.0 ([#250](https://github.com/gma1k/podtrace/issues/250)) ([5df4780](https://github.com/gma1k/podtrace/commit/5df47800fd644ef137f307359877eb6d338f6f69))
* **deps:** update module github.com/cilium/ebpf to v0.22.0 ([#252](https://github.com/gma1k/podtrace/issues/252)) ([681c607](https://github.com/gma1k/podtrace/commit/681c607e484d19ef688aa15e5768c60517650f8b))

## [0.13.3](https://github.com/gma1k/podtrace/compare/v0.13.2...v0.13.3) (2026-06-22)


### Features

* detect unprivileged AF_ALG aead binds (CVE-2026-31431 Copy-Fail) ([#243](https://github.com/gma1k/podtrace/issues/243)) ([3b6c49f](https://github.com/gma1k/podtrace/commit/3b6c49f66d6980501cb62fd7161036b7184a581e))
* wire PII redaction through TracerConfig and honor custom rules ([#242](https://github.com/gma1k/podtrace/issues/242)) ([7d82d3c](https://github.com/gma1k/podtrace/commit/7d82d3cdc72b166acce6be779db338386b377743))


### Maintenance

* **deps:** pin helm to v4.2.2 and free runner disk in chainsaw ([#240](https://github.com/gma1k/podtrace/issues/240)) ([f9ea5fa](https://github.com/gma1k/podtrace/commit/f9ea5fa08eb756bc7d018f27d5801fb031a27a5d))
* **deps:** update docker/dockerfile docker tag to v1.25 ([#238](https://github.com/gma1k/podtrace/issues/238)) ([dfc1c7a](https://github.com/gma1k/podtrace/commit/dfc1c7a1493cc614df2184e22f18b53be6dc8140))
* **deps:** update github actions to v3.0.1 ([#241](https://github.com/gma1k/podtrace/issues/241)) ([3da05f3](https://github.com/gma1k/podtrace/commit/3da05f327fcbfba3d84f5156f7eec3a0995861aa))
* **deps:** update github actions to v7 ([#239](https://github.com/gma1k/podtrace/issues/239)) ([307fe16](https://github.com/gma1k/podtrace/commit/307fe161667e38022dc101c87f8b95fd4958428c))
* **deps:** update go modules (non-major) ([#236](https://github.com/gma1k/podtrace/issues/236)) ([8722398](https://github.com/gma1k/podtrace/commit/87223988f0aa9de713da2abb4ecd3e5a70afd744))
* **deps:** update go modules (non-major) ([#244](https://github.com/gma1k/podtrace/issues/244)) ([a40827c](https://github.com/gma1k/podtrace/commit/a40827c7101104bbb13fefc7138590c3ca08296f))
* **deps:** update go modules (non-major) to v1.14.0 ([#235](https://github.com/gma1k/podtrace/issues/235)) ([bcae399](https://github.com/gma1k/podtrace/commit/bcae399cd152e5e4e3a25f30356ab0da4331686e))
* **deps:** update go modules (non-major) to v1.8.0 ([#233](https://github.com/gma1k/podtrace/issues/233)) ([8308935](https://github.com/gma1k/podtrace/commit/83089350fe41a61543829908cf25a9a7a782bdda))

## [0.13.2](https://github.com/gma1k/podtrace/compare/v0.13.1...v0.13.2) (2026-06-13)


### Bug Fixes

* **ci:** download static bpftool ([#231](https://github.com/gma1k/podtrace/issues/231)) ([c06df08](https://github.com/gma1k/podtrace/commit/c06df0800c7f48dc766c950700c96014e9d4096a))

## [0.13.1](https://github.com/gma1k/podtrace/compare/v0.13.0...v0.13.1) (2026-06-13)


### Bug Fixes

* **ci:** guarantee a working bpftool on hosted runners for the release BTF guard ([#229](https://github.com/gma1k/podtrace/issues/229)) ([494bae0](https://github.com/gma1k/podtrace/commit/494bae0bd63f70473b6dab27ba389d7098f7c6db))

## [0.13.0](https://github.com/gma1k/podtrace/compare/v0.12.10...v0.13.0) (2026-06-13)


### Features

* deliver per-cgroup resource-limit alerts from the agent ([#224](https://github.com/gma1k/podtrace/issues/224)) ([3c25113](https://github.com/gma1k/podtrace/commit/3c25113cad954829aeed58bb3c09b13969f10d2d))


### Bug Fixes

* harden agent routing, k8s resolution, and nodespawn lifecycle ([#217](https://github.com/gma1k/podtrace/issues/217)) ([f77680a](https://github.com/gma1k/podtrace/commit/f77680a229664d2a729ce52079679c7276c9974d))
* harden CLI lifecycle, bundle wire format, and tracer engine ([#220](https://github.com/gma1k/podtrace/issues/220)) ([b3b9de4](https://github.com/gma1k/podtrace/commit/b3b9de4fd297ac5c7cc9e17c2d4ed60ba4530011))
* harden exporters, alerting, metrics, and resource monitoring ([#218](https://github.com/gma1k/podtrace/issues/218)) ([8ecb383](https://github.com/gma1k/podtrace/commit/8ecb3830a72145e3ea80d3438fdc5ea00a3951a7))
* harden operator reconcile loops against conflict and drift ([#215](https://github.com/gma1k/podtrace/issues/215)) ([dc0a96d](https://github.com/gma1k/podtrace/commit/dc0a96d8d0e2d438bc7e5cfc81dc0680feb7f8af))
* make BPF builds BTF-complete and harden chart, CI, and tests ([#221](https://github.com/gma1k/podtrace/issues/221)) ([1218381](https://github.com/gma1k/podtrace/commit/1218381fa2913c6b23fe30b5502a88d5a27fc577))
* **renovate:** match helm uses-with dep name so v4.2.1 skip applies ([9de9ef0](https://github.com/gma1k/podtrace/commit/9de9ef0e1f88d152c7edc2e2e45273114089a0a0))
* **renovate:** replace removed ignoreVersions with allowedVersions ([#227](https://github.com/gma1k/podtrace/issues/227)) ([13fbb18](https://github.com/gma1k/podtrace/commit/13fbb18fac66e080281c4aa4cea9792886ca2437))


### Maintenance

* **deps:** update github actions to v4.2.1 ([#219](https://github.com/gma1k/podtrace/issues/219)) ([310c40d](https://github.com/gma1k/podtrace/commit/310c40d51adbaa787ca166586cc306628c502c3f))
* **deps:** update kubernetes ecosystem to v0.36.2 ([#223](https://github.com/gma1k/podtrace/issues/223)) ([cfbeebd](https://github.com/gma1k/podtrace/commit/cfbeebd9c01d8aad31eb68fe0c642c560efa7074))
* trigger release 0.13.0 ([#226](https://github.com/gma1k/podtrace/issues/226)) ([85d0df6](https://github.com/gma1k/podtrace/commit/85d0df65da0973bcbac042c24af2e8d920656892))

## [0.12.10](https://github.com/gma1k/podtrace/compare/v0.12.9...v0.12.10) (2026-06-11)


### Features

* add auto rebase for olm auto release script ([#205](https://github.com/gma1k/podtrace/issues/205)) ([e61de99](https://github.com/gma1k/podtrace/commit/e61de992b61fcdd04f41d2c6b730aeec3d8f2b02))


### Bug Fixes

* export spans once, surface exporter errors, tee event pipeline ([#208](https://github.com/gma1k/podtrace/issues/208)) ([1247be8](https://github.com/gma1k/podtrace/commit/1247be80b90312b4496b4c8a6a62c55d9126ae8e))
* rate-based utilization, metric caps, probe lifecycle, GCS abort ([#209](https://github.com/gma1k/podtrace/issues/209)) ([2df8803](https://github.com/gma1k/podtrace/commit/2df8803e03c3c599e52fd0ce48473ce183b5f7b7))
* wire OLM bootstrap image and split quickstart manifests ([#211](https://github.com/gma1k/podtrace/issues/211)) ([4ed4ece](https://github.com/gma1k/podtrace/commit/4ed4eceeb80cc0fba667292f5b2480b789490e7f))
* wire systemNamespace override, OTLP headers, exporter close order ([#207](https://github.com/gma1k/podtrace/issues/207)) ([e559c5b](https://github.com/gma1k/podtrace/commit/e559c5ba2f4d109244abe05266dc3ad7d2fd25b6))


### Maintenance

* **deps:** update github actions to v3.21.0 ([#212](https://github.com/gma1k/podtrace/issues/212)) ([01cbf31](https://github.com/gma1k/podtrace/commit/01cbf318dc87b3efebd77dd77a1433c1d21aeef0))
* **deps:** update github actions to v4 ([#214](https://github.com/gma1k/podtrace/issues/214)) ([85ee02b](https://github.com/gma1k/podtrace/commit/85ee02b9d3aa56e7edde18734d3ac92209955943))
* **deps:** update go modules (non-major) ([#210](https://github.com/gma1k/podtrace/issues/210)) ([6ebf36c](https://github.com/gma1k/podtrace/commit/6ebf36c0ac3420ad2f9ef06dffc163d08f2c87f0))

## [0.12.9](https://github.com/gma1k/podtrace/compare/v0.12.8...v0.12.9) (2026-06-10)


### Features

* revive dead eBPF probes and correct event data semantics ([#204](https://github.com/gma1k/podtrace/issues/204)) ([d625421](https://github.com/gma1k/podtrace/commit/d625421c5a834b2d15d19f32ae44f34d8645403f))


### Bug Fixes

* add ApplicationTrace to OLM CSV and sync operator RBAC ([#200](https://github.com/gma1k/podtrace/issues/200)) ([3386d3a](https://github.com/gma1k/podtrace/commit/3386d3a7e5f8fe1a5c435cf8dcacb9cd2b183260))
* anchor BPF event timestamps to wall clock ([#202](https://github.com/gma1k/podtrace/issues/202)) ([fdec2a4](https://github.com/gma1k/podtrace/commit/fdec2a4296468540f126e3c47d3bce567490f952))


### Maintenance

* **deps:** update go modules (non-major) ([#203](https://github.com/gma1k/podtrace/issues/203)) ([2e2fe21](https://github.com/gma1k/podtrace/commit/2e2fe214b1b6a6b51016039989f89465bc82410a))

## [0.12.8](https://github.com/gma1k/podtrace/compare/v0.12.7...v0.12.8) (2026-06-08)


### Features

* add application targeting appSelector and ApplicationTrace CRD ([#197](https://github.com/gma1k/podtrace/issues/197)) ([27d15f4](https://github.com/gma1k/podtrace/commit/27d15f46debe899318546b053327a6b614b90179))


### Tests

* improve coverage; fix nondeterministic mode-loop select ([#198](https://github.com/gma1k/podtrace/issues/198)) ([06f45a7](https://github.com/gma1k/podtrace/commit/06f45a7e14d08243801c8fa5b4cda907555bc877))


### Maintenance

* **deps:** update github actions to v6.0.2 ([#194](https://github.com/gma1k/podtrace/issues/194)) ([e2c4138](https://github.com/gma1k/podtrace/commit/e2c413829a93609e60ae6ea6280345b2bc908c7d))
* **deps:** update github actions to v7 ([#195](https://github.com/gma1k/podtrace/issues/195)) ([e4bb67c](https://github.com/gma1k/podtrace/commit/e4bb67c5a818685ca78d55c0c92a2487afcecbc8))
* **deps:** update go modules (non-major) ([#199](https://github.com/gma1k/podtrace/issues/199)) ([f5502d7](https://github.com/gma1k/podtrace/commit/f5502d77f0d7f8e3a11d335b3908add5ab02357d))

## [0.12.7](https://github.com/gma1k/podtrace/compare/v0.12.6...v0.12.7) (2026-06-06)


### Bug Fixes

* bucket timeline by event clock and clarify DNS fallback log ([#192](https://github.com/gma1k/podtrace/issues/192)) ([b96b0bb](https://github.com/gma1k/podtrace/commit/b96b0bbf66ec187451944ce1422661f77ed8b6ce))

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
