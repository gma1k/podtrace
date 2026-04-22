# syntax=docker/dockerfile:1.7
#
# Podtrace container image.
#
# Single builder stage that has both the Go toolchain and the clang+libbpf
# toolchain. Produces the eBPF object, then embeds it into the static Go
# binary. The runtime stage is distroless and carries only the binary.
#
# The same image serves the CLI, the agent DaemonSet, the operator
# Deployment, and per-session Jobs — one binary, multiple subcommands.

ARG GO_VERSION=1.25.9
ARG DEBIAN_RELEASE=trixie

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-${DEBIAN_RELEASE} AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      clang \
      llvm \
      libbpf-dev \
      libelf-dev \
      make \
      pkg-config \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Prime the module cache first for better layer reuse on source-only changes.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETARCH=amd64
ARG TARGETOS=linux
ARG VERSION=dev
ARG COMMIT=unknown

# The Makefile derives BPF_GOARCH from `go env GOARCH`; override to match the
# image's target platform so cross-builds produce a BPF object with the
# correct __TARGET_ARCH_* define (pt_regs layout differs across architectures).
ENV BPF_GOARCH=${TARGETARCH} \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

# Build the BPF object first. When bpftool or /sys/kernel/btf/vmlinux is
# unavailable (always true inside image builders), the Makefile falls back
# to the committed bpf/vmlinux.h stub. That is CO-RE-correct for the probes
# that rely on stub-defined types; gRPC/FastCGI iov_iter probes pick up
# runtime BTF from the node kernel at pod start.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    make bpf/podtrace.bpf.o

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build \
      -trimpath \
      -ldflags "-s -w -X github.com/podtrace/podtrace/internal/config.Version=${VERSION} -X github.com/podtrace/podtrace/internal/config.Commit=${COMMIT}" \
      -o /out/podtrace \
      ./cmd/podtrace


FROM gcr.io/distroless/static-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="podtrace" \
      org.opencontainers.image.description="eBPF-based troubleshooting tool for Kubernetes pods (CLI, agent, operator)" \
      org.opencontainers.image.source="https://github.com/podtrace/podtrace" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /out/podtrace /usr/local/bin/podtrace

# CLI and operator Deployment run unprivileged as 65532:65532 (distroless
# nonroot). The agent DaemonSet and session Jobs override runAsUser to 0
# and add CAP_BPF/CAP_SYS_ADMIN/CAP_PERFMON in their securityContext.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/podtrace"]
