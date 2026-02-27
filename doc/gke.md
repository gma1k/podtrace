# Running podtrace on Google Kubernetes Engine (GKE)

## Node requirements

| Requirement | Standard node pools | GKE Autopilot |
|-------------|--------------------:|:--------------|
| Kernel BPF kprobes | ✅ Supported | ❌ Not supported |
| BTF available | ✅ (COS, Ubuntu) | N/A |
| cgroup v2 | ✅ Default since GKE 1.26 | N/A |
| Container runtime | containerd | containerd |

**GKE Autopilot does not support BPF kprobes.** Use Standard node pools.

## Build

Build on any Linux machine with kernel 5.8+ or cross-compile:

```bash
sudo ./scripts/install-deps.sh   # installs clang, libbpf-dev, bpftool, Go
make build
```

## CRI socket

GKE nodes use containerd at the standard path `/run/containerd/containerd.sock`,
which podtrace tries automatically.

## Cgroup layout

GKE uses the systemd cgroup driver with cgroup v2:

```
/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/
  kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope/
```

podtrace's kubelet cgroup-parent auto-detection reads `--cgroup-root` from the
kubelet cmdline and adds it to the search candidates automatically.

## DaemonSet deployment

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: podtrace
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: podtrace
        image: your-registry/podtrace:latest
        securityContext:
          privileged: true          # or use capabilities below
          # capabilities:
          #   add: [BPF, SYS_ADMIN, SYS_RESOURCE, NET_ADMIN]
        volumeMounts:
        - name: sys-fs-cgroup
          mountPath: /sys/fs/cgroup
          readOnly: true
        - name: proc
          mountPath: /proc
          readOnly: true
        env:
        - name: PODTRACE_CGROUP_BASE
          value: /sys/fs/cgroup
        - name: PODTRACE_PROC_BASE
          value: /proc
      volumes:
      - name: sys-fs-cgroup
        hostPath:
          path: /sys/fs/cgroup
      - name: proc
        hostPath:
          path: /proc
      tolerations:
      - operator: Exists
```

## Workload Identity

If you run podtrace in a DaemonSet and need to call the Kubernetes API,
annotate the service account for Workload Identity:

```bash
kubectl annotate serviceaccount podtrace \
  iam.gke.io/gcp-service-account=podtrace@PROJECT.iam.gserviceaccount.com
```

## Known issues

- **GKE Sandbox (gVisor)** nodes use a different kernel interface; kprobes are
  not available. Use standard nodes.
- **COS nodes** include BTF in the kernel image; no extra packages needed.
- **Ubuntu nodes** on GKE also ship with BTF; bpftool is available in the node
  OS image.
