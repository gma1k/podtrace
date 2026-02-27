# Running podtrace on Talos Linux

## Overview

Talos Linux is an immutable, minimal OS designed exclusively for Kubernetes.
Key characteristics relevant to podtrace:

- **Read-only rootfs** — no package manager, cannot install tools on the node
- **No shell** by default (v1.3+ exposes a maintenance shell via `talosctl`)
- **containerd** as the CRI at `/run/containerd/containerd.sock`
- **systemd-free** — Talos uses its own init system (`machined`)
- **BTF-enabled kernels** — all official Talos kernels since v1.3 include BTF
- **cgroup v2** with cgroupfs driver (not systemd)
- **Kernel 6.1+** (Talos ≥ v1.3) — fully satisfies podtrace's 5.8+ requirement

## Build (cross-compile from a separate machine)

You cannot build directly on a Talos node. Build on any Linux machine:

```bash
# Install dependencies (Debian/Ubuntu):
sudo ./scripts/install-deps.sh

# Build for amd64 Talos nodes:
make build GOARCH=amd64

# Or for arm64 Talos nodes:
make build GOARCH=arm64
```

## Deploying podtrace on Talos

The recommended approach is a **DaemonSet** with the binary embedded in a
container image.

### Container image example

```dockerfile
FROM debian:12-slim AS builder
RUN apt-get update && apt-get install -y make clang llvm libbpf-dev bpftool
COPY . /src
WORKDIR /src
RUN make build

FROM debian:12-slim
COPY --from=builder /src/bin/podtrace /podtrace
ENTRYPOINT ["/podtrace"]
```

### DaemonSet

Talos nodes use the **cgroupfs** driver (not systemd), so cgroup paths look like:

```
/sys/fs/cgroup/kubepods/burstable/pod<uid>/<container-id>/
```

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: podtrace
  namespace: kube-system
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: podtrace
        image: your-registry/podtrace:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: sys-fs-cgroup
          mountPath: /sys/fs/cgroup
          readOnly: true
        - name: proc
          mountPath: /proc
          readOnly: true
        - name: cri-sock
          mountPath: /run/containerd/containerd.sock
        env:
        - name: PODTRACE_CGROUP_BASE
          value: /sys/fs/cgroup
        - name: PODTRACE_PROC_BASE
          value: /proc
        - name: PODTRACE_CRI_ENDPOINT
          value: unix:///run/containerd/containerd.sock
        # Talos may not embed container ID in cgroup path:
        - name: PODTRACE_ALLOW_BROAD_CGROUP
          value: "1"
      volumes:
      - name: sys-fs-cgroup
        hostPath:
          path: /sys/fs/cgroup
      - name: proc
        hostPath:
          path: /proc
      - name: cri-sock
        hostPath:
          path: /run/containerd/containerd.sock
          type: Socket
      tolerations:
      - operator: Exists
```

## BTF on Talos

Since Talos kernels include BTF, `bpf/vmlinux.h` is auto-regenerated from
`/sys/kernel/btf/vmlinux` at build time when `bpftool` is available. In a
cross-compiled build (no Talos BTF available), the placeholder `bpf/vmlinux.h`
is used — this still works but without full CO-RE type safety.

For production deployments, generate `vmlinux.h` from a running Talos node:

```bash
# From the build machine, using talosctl:
talosctl read /sys/kernel/btf/vmlinux > /tmp/talos-vmlinux
bpftool btf dump file /tmp/talos-vmlinux format c > bpf/vmlinux.h
make build
```

## Known issues

- **No systemd** — the kubelet cgroup-parent auto-detection via `/proc/<pid>/cmdline`
  works normally since kubelet still runs as a process.
- **cgroupfs driver** — Talos uses the cgroupfs driver. If the kubelet process is
  not visible in `/proc` (e.g. running in a separate namespace), set
  `PODTRACE_CGROUP_BASE=/sys/fs/cgroup` explicitly.
- **Talos API restrictions** — some Talos machine config hardening options can
  restrict `/proc` visibility. Ensure `hostPID: true` is allowed by your Talos
  machine config.
