#!/usr/bin/env bash
# Load the freshly built BPF object through the real kernel verifier inside a
# privileged container. Catches verifier rejections (instruction-budget
# blowups, modified-ctx dereferences, ...) that compilation cannot: container
# images build from the stub vmlinux.h, where the BTF-only programs compile
# to no-ops and therefore never face the verifier in CI or in-cluster.
set -euo pipefail

cd "$(dirname "$0")/.."

ARCH="$(go env GOARCH)"
OBJ="internal/ebpf/embedded/podtrace.${ARCH}.bpf.o"
[[ -f "${OBJ}" ]] || {
	echo "missing ${OBJ} — run 'make build' first" >&2
	exit 1
}

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

cp hack/bpfloadtest/main.go "${WORKDIR}/"
cp "${OBJ}" "${WORKDIR}/object.bpf.o"
EBPF_VERSION="$(grep 'github.com/cilium/ebpf' go.mod | awk '{print $2}')"
(
	cd "${WORKDIR}"
	printf 'module bpfloadtest\n\ngo 1.24\n' >go.mod
	go mod edit -require "github.com/cilium/ebpf@${EBPF_VERSION}"
	go mod tidy >/dev/null 2>&1
	CGO_ENABLED=0 go build -o loader .
)

docker run --rm --privileged -v "${WORKDIR}":/lt debian:bookworm-slim /lt/loader /lt/object.bpf.o
