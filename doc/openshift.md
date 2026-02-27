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

## CRI socket

CRI-O sockets tried automatically:

- `/run/crio/crio.sock`
- `/var/run/crio/crio.sock`

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
oc adm policy add-scc-to-user privileged -z podtrace -n <namespace>
```

## Security Context Constraints

Create a dedicated SCC for podtrace to avoid granting full `privileged`:

```yaml
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: podtrace-scc
allowPrivilegedContainer: false
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

Apply: `oc apply -f podtrace-scc.yaml && oc adm policy add-scc-to-user podtrace-scc -z podtrace`

## Cgroup path mismatch (PODTRACE_ALLOW_BROAD_CGROUP)

CRI-O on OpenShift may return a cgroup path that does not contain the full
container ID in the directory name. This triggers podtrace's safety check.

**Set `PODTRACE_ALLOW_BROAD_CGROUP=1`** in the DaemonSet environment to bypass
the check. podtrace will still scope tracing to the correct cgroup via kernel-
side cgroup ID filtering.

## DaemonSet deployment

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: podtrace
  namespace: podtrace
spec:
  template:
    spec:
      serviceAccountName: podtrace
      hostPID: true
      hostNetwork: true
      containers:
      - name: podtrace
        image: your-registry/podtrace:latest
        securityContext:
          capabilities:
            add: [BPF, SYS_ADMIN, SYS_RESOURCE, NET_ADMIN]
          seLinuxOptions:
            type: spc_t       # super-privileged container type
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
        - name: PODTRACE_ALLOW_BROAD_CGROUP
          value: "1"
        - name: PODTRACE_CRI_ENDPOINT
          value: unix:///run/crio/crio.sock
      volumes:
      - name: sys-fs-cgroup
        hostPath:
          path: /sys/fs/cgroup
      - name: proc
        hostPath:
          path: /proc
```

## Known issues

- **RHEL 8 kernels** (4.18) are below the 5.8 requirement for BPF ring buffers.
  OpenShift 4.14+ on RHEL 9 uses kernel 5.14+ which fully supports podtrace.
  On older RHEL 8 nodes, BPF perf buffer fallback is not yet implemented.
- **BTF on RHEL 8**: not available by default; install `kernel-devel` and use
  `PODTRACE_BTF_FILE` to point to a matching BTF file.
