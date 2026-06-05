# Running podtrace on Talos Linux

## Using `kubectl podtrace`

The CLI works on Talos out-of-the-box. It identifies the node
hosting the target pod, spawns a short-lived privileged pod on that
node, runs eBPF there, and streams events back to your terminal. The
workstation pre-resolves the target's containerID and passes it via a
flag so the spawn pod needs **zero RBAC** — see [cli-architecture.md](cli-architecture.md).
This replaces the old workstation-eBPF mode that silently failed on Talos
because Talos's container runtime is isolated from the host that ran
`kubectl podtrace` (issue [#149](https://github.com/gma1k/podtrace/issues/149)).

```bash
# One-time: allow the spawn pod's privileged spec in the target namespace
kubectl label ns/<your-app-ns> pod-security.kubernetes.io/enforce=privileged --overwrite

# Then trace as normal
kubectl podtrace -n <your-app-ns> <pod-name>
```

If you'd rather keep your application namespaces non-privileged,
create a dedicated namespace once and aim the spawn at it:

```bash
kubectl create ns podtrace-cli
kubectl label ns/podtrace-cli pod-security.kubernetes.io/enforce=privileged
export PODTRACE_SPAWN_NAMESPACE=podtrace-cli
kubectl podtrace -n <app-ns> <pod>
```

### Air-gapped Talos clusters

The spawn pod pulls `ghcr.io/gma1k/podtrace:<CLI version>` by default.
Pre-pull on each node or point at a mirror:

```bash
talosctl --nodes <nodes> image pull ghcr.io/gma1k/podtrace:<version>
# or
kubectl podtrace --image=mirror.internal/podtrace:<tag> ...
```

### Local dev/testing against a Talos cluster

To exercise an in-development binary on a real Talos VM cluster:

```bash
# Build a dev image
make docker-build IMAGE_REPO=10.5.0.1:5000/podtrace IMAGE_TAG=dev

# Push to a local registry reachable from Talos VMs
docker run -d --name pt-reg -p 10.5.0.1:5000:5000 registry:2
docker push 10.5.0.1:5000/podtrace:dev

# Tell Talos to allow the insecure registry
talosctl --nodes <nodes> patch machineconfig --immediate -p '[
  {"op":"add","path":"/machine/registries","value":{
    "config":{"10.5.0.1:5000":{"tls":{"insecureSkipVerify":true}}}
  }}
]'

# Pre-pull and run
talosctl --nodes <nodes> image pull 10.5.0.1:5000/podtrace:dev
./bin/podtrace --pods <ns>/<pod> --image=10.5.0.1:5000/podtrace:dev --diagnose 5s
```

A turnkey Talos QEMU cluster setup that was used to validate this fix
lives at [`stuffs/talos-setup/`](https://github.com/gma1k/podtrace) in the user's
local workspace; the `scripts/up.sh` script brings up a Talos v1.13.2
cluster with Cilium in ~3 minutes.

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

## Production deployment via Helm

Use the operator + agent chart. The agent DaemonSet runs on every node and
reconciles eBPF attachments from `PodTrace` / `PodTraceSession` /
`PodTraceSchedule` CRs:

```bash
# cert-manager is required for the validating webhook's TLS certs
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set crds.enabled=true

# self-signed Issuer for the webhook cert
kubectl create namespace podtrace-system
kubectl apply -f - <<'EOF'
apiVersion: cert-manager.io/v1
kind: Issuer
metadata: {name: podtrace-selfsigned, namespace: podtrace-system}
spec: {selfSigned: {}}
EOF

# Install podtrace
helm install podtrace oci://ghcr.io/gma1k/charts/podtrace \
  --namespace podtrace-system \
  --set webhook.enabled=true
```

After install you get:

- **Operator** Deployment reconciling 5 CRDs (`PodTrace`, `PodTraceSession`,
  `PodTraceSchedule`, `ExporterConfig`, `TracerConfig`)
- **Agent** DaemonSet — one privileged pod per node, attaches eBPF locally,
  filters events by cgroup_id
- **Validating webhook** — admits only well-formed CRs (must have cert-manager)
- **Default `TracerConfig`** — controls the agent image / resources

Talos nodes use **cgroup v2 with the cgroupfs driver**; the agent
auto-detects this and uses paths like
`/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/.../cri-containerd-<id>.scope`.
No env-var overrides needed for default Talos installs.

### Verifying the install

```bash
kubectl -n podtrace-system get pods
# expect: podtrace-operator Running, podtrace-agent (N) Running

kubectl get crd | grep podtrace.io
# expect: 5 CRDs

kubectl get validatingwebhookconfigurations | grep podtrace
# expect: podtrace-validating-webhook
```

End-to-end smoke test:

```bash
kubectl apply -f - <<'EOF'
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata: {name: smoke, namespace: default}
spec:
  type: otlp
  otlp: {endpoint: collector.default.svc.cluster.local:4318}
---
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata: {name: smoke, namespace: default}
spec:
  selector: {matchLabels: {app: nginx}}
  duration: 10s
  exporterRef: {name: smoke}
  reportRef: {configMap: {name: smoke-report}}
EOF

# Session runs a Job on the target's node, finishes within ~15s
kubectl wait --for=jsonpath='{.status.state}'=Completed \
  podtracesession smoke --timeout=60s
kubectl get cm smoke-report -o jsonpath='{.data.report\.txt}'
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

## Hardening trade-offs

Talos's secure defaults affect what podtrace can display. Each item below is
an intentional kernel/Kubernetes choice; podtrace surfaces a clear message and
the workaround if you accept the security cost.

### Kernel Lockdown LSM `confidentiality` mode blocks BPF entirely

Talos boots with `lockdown=confidentiality` on the kernel command line, the
strictest setting of the Lockdown LSM. In this mode the kernel denies *all*
BPF reads of kernel RAM — including the modern `bpf_probe_read_kernel`,
`bpf_probe_read_kernel_str` helpers, and the CO-RE `BPF_CORE_READ` macro that
podtrace relies on for almost every program. The verifier rejects the load
with a misleading helper-id message (the helper number printed isn't stable
across runs), but the real cause is visible in `dmesg`:

```
Lockdown: podtrace: use of bpf to read kernel RAM is restricted; see man kernel_lockdown.7
```

Podtrace v0.12.2+ detects this at startup and fails fast:

> Error: kernel Lockdown LSM is in 'confidentiality' mode
> (/sys/kernel/security/lockdown). BPF programs cannot read kernel RAM in this
> mode … On Talos: drop `lockdown=confidentiality` from
> `.machine.install.extraKernelArgs` …

To fix, patch the machine config to drop `lockdown=confidentiality` (or set it
to `lockdown=none` / `lockdown=integrity`):

```yaml
machine:
  install:
    extraKernelArgs:
      - lockdown=none
```

Apply and reboot the node:

```bash
talosctl --nodes <node> patch machineconfig --immediate -p @patch.yaml
talosctl --nodes <node> reboot
```

Confirm:

```bash
talosctl --nodes <node> read /sys/kernel/security/lockdown
# expected: [none] integrity confidentiality
```

This is the largest security trade-off in this document — confidentiality mode
specifically exists to prevent any read of kernel RAM by any unprivileged path,
including BPF. `integrity` (a middle ground) prevents kernel-RAM *writes* but
permits the reads podtrace needs; it's the recommended setting for nodes you
trace regularly. Power users on test kernels can set
`PODTRACE_SKIP_LOCKDOWN_CHECK=1` to bypass the check (the BPF load will then
fail with the misleading verifier error).

### Kernel stack symbolication needs `kernel.kptr_restrict=0`

Talos defaults `kernel.kptr_restrict=2`, which zeroes every address in
`/proc/kallsyms` regardless of capability — `CAP_SYSLOG` doesn't help.
The sysctl exists to deny userspace any address that could be used as an exploit
primitive (ROP gadgets, SMEP/SMAP bypasses).

There is no userspace API that returns real kernel addresses when
`kptr_restrict=2` is in effect — not BTF, not `bpf_kallsyms_lookup_name`,
not `bpf_get_func_ip`. Podtrace falls back to raw hex (`0xffffffff97dd580e`)
and emits a one-shot warning:

> Kernel symbol resolution unavailable: /proc/kallsyms returned no addresses
> (kernel.kptr_restrict is non-zero). Stack frames at kernel addresses will
> display as raw hex. Set kernel.kptr_restrict=0 on the node to enable symbolication.

User-space frames (your app's stack) symbolicate normally via `/proc/<pid>/exe`
+ `addr2line`. To enable kernel-side symbolication, patch the machine config:

```yaml
machine:
  sysctls:
    kernel.kptr_restrict: "0"
```

`talosctl --nodes <node> patch machineconfig --immediate -p @patch.yaml`

This is a security trade-off — `kptr_restrict=0` exposes kernel addresses to
all processes on the node and weakens exploit mitigations. Apply per node only
when actively debugging; revert when done. User-space stack frames (your app's
code) symbolicate normally regardless via `/proc/<pid>/exe` + `addr2line`.

### PodSecurity admission on workload namespaces

The spawn pod needs `hostPID` + `CAP_BPF` + `CAP_SYS_ADMIN`, which clusters
enforcing `restricted` PodSecurity block by default. Three options:

1. Label the target namespace: `kubectl label ns/<app-ns> pod-security.kubernetes.io/enforce=privileged --overwrite`
2. Use a dedicated namespace and set `PODTRACE_SPAWN_NAMESPACE=podtrace-cli`.
3. Use the operator path (CR-driven sessions in `podtrace-system`) — already
   pre-allowed by the helm chart.

### DNS tracking needs a libc in the traced container

DNS name resolution is traced by attaching a uprobe to `getaddrinfo` in the
**workload container's** libc. If the target is a statically-linked binary
(common for Go images) or runs on a distroless/scratch base, there is no libc
to probe and podtrace emits a one-shot message at startup:

> DNS tracking disabled: no libc found in the target container (e.g. a
> statically-linked binary or distroless/scratch image). DNS name resolution
> will not be traced; other tracing is unaffected.

This is expected and harmless — every other tracer (network, filesystem, CPU,
memory, syscalls) works regardless. There is nothing to fix on the node; it is
a property of the image being traced. To get DNS names, trace a workload whose
image ships a dynamic glibc or musl libc.

### Kubernetes event correlation runs on the workstation (no spawn-pod RBAC)

As an enhancement, the CLI correlates your app's activity with Kubernetes
`Events` on the target pod and prints a **"Kubernetes Events" section** after the
trace. This watch runs on your **workstation**, using your kubeconfig, which can
already watch events (you can run `kubectl get events`). The spawn pod keeps its
**zero-RBAC** design and is never involved in this lookup.

If your own kubeconfig is restricted and cannot watch events, the section is
simply skipped with a one-shot, non-fatal message; tracing is unaffected:

> Kubernetes event correlation skipped: your kubeconfig cannot watch events in
> namespace <ns>. Tracing is unaffected.

### What works without any extra config

- cgroupfs path discovery (auto-detects Talos's `kubelet.slice/...` layout)
- BTF loading from `/sys/kernel/btf/vmlinux` (all Talos kernels ≥ 1.3 ship BTF)
- containerd via `/run/containerd/containerd.sock`
- User-space stack symbolication (addr2line on `/proc/<pid>/exe`)
- All 5 CRDs reconciling
- Validating webhook (once cert-manager is installed)
- Chainsaw e2e suite (validated 13/13 functional)
