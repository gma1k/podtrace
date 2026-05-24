# syntax=docker/dockerfile:1.24
#
# Podtrace container image.
#
# Single builder stage that has both the Go toolchain and the clang+libbpf
# toolchain. Produces the eBPF object, then embeds it into the static Go
# binary. The runtime stage is distroless and carries only the binary.
#
# The same image serves the CLI, the agent DaemonSet, the operator
# Deployment, and per-session Jobs — one binary, multiple subcommands.

ARG GO_VERSION=1.26.3
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

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETARCH=amd64
ARG TARGETOS=linux
ARG VERSION=dev
ARG COMMIT=unknown
ARG IMAGE_REPO=ghcr.io/gma1k/podtrace

ENV BPF_GOARCH=${TARGETARCH} \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    if [ -s internal/ebpf/embedded/podtrace.${BPF_GOARCH}.bpf.o ]; then \
        touch internal/ebpf/embedded/podtrace.${BPF_GOARCH}.bpf.o; \
        echo "Reusing prebuilt BPF object from build context"; \
    else \
        make internal/ebpf/embedded/podtrace.${BPF_GOARCH}.bpf.o; \
    fi

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build \
      -trimpath \
      -tags embed_bpf \
      -ldflags "-s -w -X github.com/podtrace/podtrace/internal/config.Version=${VERSION} -X github.com/podtrace/podtrace/internal/config.Commit=${COMMIT} -X github.com/podtrace/podtrace/internal/config.Image=${IMAGE_REPO}" \
      -o /out/podtrace \
      ./cmd/podtrace


FROM gcr.io/distroless/static-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="podtrace" \
      org.opencontainers.image.description="eBPF-based troubleshooting tool for Kubernetes pods (CLI, agent, operator)" \
      org.opencontainers.image.source="https://github.com/gma1k/podtrace" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /out/podtrace /usr/local/bin/podtrace

ENTRYPOINT ["/usr/local/bin/podtrace"]
