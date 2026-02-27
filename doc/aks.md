# Running podtrace on Azure Kubernetes Service (AKS)

## Node requirements

AKS system nodes run Ubuntu 22.04 with a 5.15+ kernel and BTF enabled by default
since AKS 1.25+. All standard node pools support BPF kprobes.

| Requirement | Ubuntu node pool | Azure Linux (CBL-Mariner) |
|-------------|:----------------|:--------------------------|
| Kernel BPF kprobes | ✅ | ✅ |
| BTF available | ✅ | ✅ |
| cgroup v2 | ✅ Default (Ubuntu 22.04) | ✅ |
| Container runtime | containerd | containerd |
| Cgroup driver | systemd | systemd |

## Build

```bash
sudo ./scripts/install-deps.sh   # Debian/Ubuntu path
make build
```

## CRI socket

AKS nodes use containerd at `/run/containerd/containerd.sock` (standard path,
tried automatically by podtrace).

## Cgroup layout

AKS uses the systemd cgroup driver. Kubelet on AKS sets `--cgroup-root=/` by
default and slice paths look like:

```
/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/
  kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope/
```

podtrace detects the kubelet `--cgroup-root` flag automatically via
`/proc/<kubelet-pid>/cmdline`.

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
          capabilities:
            add: [BPF, SYS_ADMIN, SYS_RESOURCE, NET_ADMIN]
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
```

## Managed Identity / AAD Workload Identity

For Kubernetes API access from within a DaemonSet pod, use AAD Workload Identity:

```bash
az aks update --resource-group RG --name CLUSTER --enable-oidc-issuer
az identity federated-credential create ...
```

## Known issues

- **Azure Confidential VMs** use SEV-SNP; kernel BPF access is unchanged but
  verify with `dmesg | grep bpf` after deployment.
- **Windows node pools** are not supported (Linux BPF only).
