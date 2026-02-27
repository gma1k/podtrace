# Running podtrace on Amazon Elastic Kubernetes Service (EKS)

## Node AMI matrix

| AMI / Node type | Kernel | cgroup | Runtime | BPF kprobes | BTF |
|-----------------|--------|--------|---------|:-----------:|:---:|
| Amazon Linux 2 (AL2) | 5.10 | v1 or v2 | containerd | ✅ | ✅ |
| Amazon Linux 2023 (AL2023) | 6.1 | v2 | containerd | ✅ | ✅ |
| Bottlerocket | 5.15+ | v2 | containerd | ✅ | ✅ |
| Ubuntu 20.04 (community) | 5.15 | v2 | containerd | ✅ | ✅ |
| Windows | N/A | N/A | — | ❌ | ❌ |
| AWS Fargate | managed | — | — | ❌ | ❌ |

**Fargate does not support BPF kprobes.** Use EC2 node groups.

## Build

```bash
sudo ./scripts/install-deps.sh   # auto-detects AL2/AL2023 → dnf
make build
```

## CRI socket paths

EKS nodes use containerd. All standard paths are tried automatically:

- `/run/containerd/containerd.sock` (AL2023, Bottlerocket, Ubuntu)
- `/var/run/containerd/containerd.sock` (AL2 legacy)
- `/run/dockershim.sock` (Bottlerocket host container proxy, older versions)

For Bottlerocket, podtrace is typically run in the **admin container** or via
the **control container** where the host filesystem is mounted. Set:

```bash
export PODTRACE_CRI_ENDPOINT=unix:///run/containerd/containerd.sock
export PODTRACE_CGROUP_BASE=/sys/fs/cgroup
```

## Cgroup layout

### Amazon Linux 2 / AL2023 (systemd driver, cgroup v2)

```
/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/
  kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope/
```

### Bottlerocket (cgroupfs driver, cgroup v2)

```
/sys/fs/cgroup/kubepods/burstable/pod<uid>/<id>/
```

podtrace auto-detects the kubelet `--cgroup-driver` from the process cmdline
and adjusts search candidates accordingly.

## DaemonSet deployment (EKS)

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
          capabilities:
            add: [BPF, SYS_ADMIN, SYS_RESOURCE, NET_ADMIN]
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
```

## Bottlerocket specifics

Bottlerocket uses an immutable OS. To run podtrace:

1. Enable the **admin container** in Bottlerocket user data:
   ```toml
   [settings.host-containers.admin]
   enabled = true
   ```
2. Enter the admin container: `apiclient exec admin`
3. Run podtrace with host mounts (`hostPID: true`, `hostNetwork: true`).
4. Set `PODTRACE_CRI_ENDPOINT=unix:///run/containerd/containerd.sock`.

## Known issues

- **AL2 with Docker**: AL2 nodes prior to EKS 1.24 used dockershim. These are
  end-of-life; upgrade to containerd-based nodes.
- **IMDSv2**: EC2 metadata calls from pods require `HttpPutResponseHopLimit ≥ 2`
  on the node's instance metadata configuration.
