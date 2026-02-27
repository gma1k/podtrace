# Running podtrace on OpenShift / OKD

## Overview

OpenShift uses CRI-O as the container runtime and enforces strict security
through Security Context Constraints (SCC). SELinux is enabled in Enforcing
mode by default on all RHEL-based OpenShift nodes.

| Requirement | OpenShift 4.x |
|-------------|:-------------|
| Container runtime | CRI-O |
| cgroup driver | systemd |
| cgroup version | v1 (≤4.13) / v2 (≥4.14) |
| SELinux | Enforcing |
| Kernel | 4.18+ (RHEL 8), 5.14+ (RHEL 9) |
| BTF | ✅ (RHEL 9 kernel), partial (RHEL 8) |

## Prerequisites

### RBAC — ClusterRole for pod resolution

podtrace needs to GET pods across namespaces. Create a `ClusterRole` and bind
it to the DaemonSet service account:

```yaml
apiVersion rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: podtrace
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: podtrace
subjects:
- kind: ServiceAccount
  name: podtrace
  namespace: podtrace
roleRef:
  kind: ClusterRole
  name: podtrace
  apiGroup: rbac.authorization.k8s.io
```

Without this, attempting to trace a pod in a namespace the service account
cannot GET will return `pods "..." not found` (OpenShift returns 404 instead
of 403 to avoid leaking resource existence).

## CRI socket

CRI-O sockets tried automatically (in order):

- `/run/crio/crio.sock`
- `/var/run/crio/crio.sock`

The DaemonSet **must** mount the host CRI-O socket (see DaemonSet YAML below).
Without the mount, all three cgroup resolution methods fail silently and the
error `cgroup path not found for container <id>` is returned.

Override with: `PODTRACE_CRI_ENDPOINT=unix:///run/crio/crio.sock`

## SELinux

podtrace detects SELinux enforcing mode at startup and logs a warning. To allow
BPF operations, either:

**Option A — Create a BPF audit policy module (preferred):**

```bash
# Run podtrace once to generate AVC denials, then:
ausearch -c podtrace --raw | audit2allow -M podtrace-bpf
semodule -i podtrace-bpf.pp
```

**Option B — Use privileged SCC:**

```yaml
# Allow the podtrace service account to use the privileged SCC:
oc adm policy add-scc-to-user privileged -z podtrace -n podtrace
```

## Security Context Constraints

Create a dedicated SCC for podtrace to avoid granting full `privileged`:

```yaml
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: podtrace-scc
allowPrivilegedContainer: false
allowHostPID: true
allowHostNetwork: true
allowedCapabilities:
- BPF
- SYS_ADMIN
- SYS_RESOURCE
- NET_ADMIN
runAsUser:
  type: RunAsAny
seLinuxContext:
  type: RunAsAny
volumes:
- hostPath
- configMap
- secret
```

Apply:

```bash
oc apply -f podtrace-scc.yaml
oc adm policy add-scc-to-user podtrace-scc -z podtrace -n podtrace
```

## DaemonSet deployment

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: podtrace
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: podtrace
  namespace: podtrace
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: podtrace
  namespace: podtrace
spec:
  selector:
    matchLabels:
      app: podtrace
  template:
    metadata:
      labels:
        app: podtrace
    spec:
      serviceAccountName: podtrace
      hostPID: true        # required: /proc fallback needs host process namespace
      hostNetwork: true
      containers:
      - name: podtrace
        image: your-registry/podtrace:latest
        securityContext:
          capabilities:
            add: [BPF, SYS_ADMIN, SYS_RESOURCE, NET_ADMIN]
          seLinuxOptions:
            type: spc_t   # super-privileged container type — bypasses SELinux checks
        volumeMounts:
        - name: crio-sock
          mountPath: /run/crio/crio.sock   # required: CRI-O socket for cgroup resolution
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
        - name: PODTRACE_CRI_ENDPOINT
          value: unix:///run/crio/crio.sock
      volumes:
      - name: crio-sock
        hostPath:
          path: /run/crio/crio.sock
          type: Socket
      - name: sys-fs-cgroup
        hostPath:
          path: /sys/fs/cgroup
      - name: proc
        hostPath:
          path: /proc
```

> **Note:** `hostPID: true` is required for the `/proc`-based cgroup fallback
> to see container processes. Without it, only the CRI-O socket and cgroup
> filesystem scan methods work.

## Cgroup resolution on OpenShift

On OpenShift ≥ 4.14 with cgroupv2 + systemd driver, CRI-O places container
cgroups under:

```
/sys/fs/cgroup/kubepods.slice/
  kubepods-besteffort.slice/
    kubepods-besteffort-pod<uid>.slice/
      crio-<container-id>.scope/
```

CRI-O's ContainerStatus response may return the path relative to the
`kubepods.slice` scope (omitting the `kubepods.slice/` prefix). podtrace
handles this automatically by trying both the direct path and the
`kubepods.slice/`-prefixed variant.

If cgroup resolution still fails, set `PODTRACE_CRI_CGROUP_FIELDS` to add
custom JSON field names to search in the CRI-O info response:

```bash
PODTRACE_CRI_CGROUP_FIELDS=linux.cgroupsPath,cgroupDirectory
```

## Known issues

- **RHEL 8 kernels** (4.18) are below the 5.8 requirement for BPF ring buffers.
  OpenShift 4.14+ on RHEL 9 uses kernel 5.14+ which fully supports podtrace.
  On older RHEL 8 nodes, BPF perf buffer fallback is not yet implemented.
- **BTF on RHEL 8**: not available by default; install `kernel-devel` and use
  `PODTRACE_BTF_FILE` to point to a matching BTF file.
- **Cross-node tracing**: podtrace traces processes on the node where it runs.
  To trace a pod, the podtrace DaemonSet pod must be on the same node. Use
  node selectors or target the correct DaemonSet pod directly.

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `pods "..." not found` | RBAC: service account cannot GET pods in that namespace | Apply the ClusterRole above |
| `cgroup path not found for container <id>` | CRI-O socket not mounted, or cgroup fs not mounted | Add `crio-sock` and `sys-fs-cgroup` volume mounts |
| `CRI endpoint not found` | Socket path wrong or not mounted | Set `PODTRACE_CRI_ENDPOINT` and mount the socket |
| `operation not permitted` (BPF) | Missing capabilities or wrong SCC | Apply `podtrace-scc` and add capabilities |
| SELinux AVC denial | SELinux blocking BPF syscalls | Create audit2allow policy or use `spc_t` |
