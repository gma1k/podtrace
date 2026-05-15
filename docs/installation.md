# Installation

## Install

Four install paths, ordered by friction:

1. **Quickstart manifest** — single `kubectl apply`, working demo, end-to-end. Best for evaluating podtrace.
2. **OperatorHub.io / OLM** — one-click install on OpenShift or any OLM-managed cluster.
3. **Helm chart** — production install with custom values,
   validating webhook, custom RBAC. Best for ongoing operation.
4. **Building from source** — for contributors or air-gapped
   clusters.

### Quickstart manifest (one-shot demo)

A pre-rendered manifest including the operator + CRDs + a sample nginx workload + a `PodTraceSession` is attached to every GitHub Release. Apply it with one command:

```bash
kubectl apply -f https://github.com/gma1k/podtrace/releases/latest/download/quickstart.yaml
```

What it deploys, in order:

| Resource | Namespace | Purpose |
|---|---|---|
| 4 CRDs (`podtrace.io`) | cluster | Operator's API surface |
| `podtrace-system` Namespace + RBAC + Deployment | `podtrace-system` | Operator runtime |
| `default` `TracerConfig` | cluster | Governs the agent DaemonSet |
| `podtrace-demo` Namespace + nginx Deployment | `podtrace-demo` | Sample workload |
| `demo-otlp` `ExporterConfig` | `podtrace-demo` | No-op OTLP target (no network calls) |
| `demo-trace` `PodTraceSession` | `podtrace-demo` | 30s diagnose against nginx |

```bash
# Session should reach state: Completed
kubectl get podtracesession demo-trace -n podtrace-demo

# Inspect status.summary (aggregated event counts)
kubectl get podtracesession demo-trace -n podtrace-demo \
  -o jsonpath='{.status.summary}{"\n"}'

# Read the full human-readable report
kubectl get cm nginx-trace-report -n podtrace-demo \
  -o jsonpath='{.data.report\.txt}'
```

The demo session has `ttlSecondsAfterFinished: 600`, so it auto-deletes itself 10 minutes after completing. To tear down everything immediately:

```bash
kubectl delete ns podtrace-system podtrace-demo
kubectl delete crd -l app.kubernetes.io/name=podtrace
```

### OperatorHub.io / OLM

On OpenShift or any cluster running [Operator Lifecycle Manager (OLM)](https://olm.operatorframework.io/),
Podtrace is published in the [OperatorHub.io community catalog](https://operatorhub.io/operator/podtrace).
This is the most ergonomic install path for OpenShift admins, one
click in the Console UI, OLM handles the operator lifecycle (install,
upgrade, RBAC).

**OpenShift Console:** Operators → OperatorHub → search "podtrace" → Install.

**CLI install via Subscription manifest**:

```bash
kubectl apply -f - <<EOF
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: podtrace
  namespace: operators
spec:
  channel: stable
  name: podtrace
  source: operatorhubio-catalog
  sourceNamespace: olm
EOF

# Wait for the InstallPlan to apply
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded \
  csv -n operators -l operators.coreos.com/podtrace.operators \
  --timeout=5m
```

To uninstall:

```bash
kubectl delete subscription podtrace -n operators
kubectl delete csv -n operators -l operators.coreos.com/podtrace.operators
kubectl delete crd -l app.kubernetes.io/name=podtrace
```

### Helm chart

For production deployments, custom values, validating webhook, multi-tenant agent config, custom RBAC — install via the published OCI Helm chart in GHCR instead:

```bash
helm install podtrace oci://ghcr.io/gma1k/charts/podtrace --version 0.1.0 \
  --namespace podtrace-system --create-namespace \
  --set operator.enabled=true
```

The chart installs CRDs, namespace, operator, agent DaemonSet, and a
default `TracerConfig`. See [operator.md](operator.md) for what each
piece does, and the [chart values reference](../deploy/charts/podtrace/values.yaml)
for available overrides.

### Verifying signatures (cosign keyless)

Every released image, chart, and CLI tarball is signed via cosign
keyless OIDC, recorded in the public Rekor transparency log. Verify
before running:

```bash
# x-release-please-version
cosign verify ghcr.io/gma1k/podtrace:0.11.0 \
  --certificate-identity-regexp 'https://github.com/gma1k/podtrace/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The image also ships an SBOM and SLSA provenance attestation:

```bash
# x-release-please-version
cosign download attestation ghcr.io/gma1k/podtrace:0.11.0 \
  --predicate-type https://spdx.dev/Document | jq .
```

The quickstart manifest ships with a `quickstart.yaml.sha256` for integrity verification:

```bash
cd $(mktemp -d)
curl -fsSLO https://github.com/gma1k/podtrace/releases/latest/download/quickstart.yaml
curl -fsSLO https://github.com/gma1k/podtrace/releases/latest/download/quickstart.yaml.sha256
sha256sum -c quickstart.yaml.sha256
```

### Install the CLI

For workstation use (interactive `podtrace` invocations from a laptop
or CI runner), separate from the cluster operator install above. Each
release ships signed tarballs for linux + macOS × amd64 + arm64:

```bash
# Linux amd64
curl -fsSL https://github.com/gma1k/podtrace/releases/latest/download/podtrace_linux_amd64.tar.gz \
  | sudo tar xz -C /usr/local/bin podtrace

# Linux arm64
curl -fsSL https://github.com/gma1k/podtrace/releases/latest/download/podtrace_linux_arm64.tar.gz \
  | sudo tar xz -C /usr/local/bin podtrace

# macOS Apple Silicon
curl -fsSL https://github.com/gma1k/podtrace/releases/latest/download/podtrace_darwin_arm64.tar.gz \
  | sudo tar xz -C /usr/local/bin podtrace

# macOS Intel
curl -fsSL https://github.com/gma1k/podtrace/releases/latest/download/podtrace_darwin_amd64.tar.gz \
  | sudo tar xz -C /usr/local/bin podtrace
```

`/usr/local/bin` is root-owned on most systems, so the tar extract needs
`sudo`. The binary already has the executable bit set inside the tarball
(preserved from `go build`), so no `chmod +x` is required.

To install without sudo, extract to a user-writable directory on `$PATH`:

```bash
mkdir -p ~/.local/bin
curl -fsSL https://github.com/gma1k/podtrace/releases/latest/download/podtrace_linux_amd64.tar.gz \
  | tar xz -C ~/.local/bin podtrace
# ensure ~/.local/bin is on $PATH (most modern shells include it by default)
```

`podtrace --version` should report the tag you installed.

#### Install via krew

If you have [krew](https://krew.sigs.k8s.io/) installed, the simplest
path is `kubectl krew install`:

```bash
kubectl krew install podtrace
kubectl podtrace --version
kubectl krew upgrade podtrace
```

#### Verify the tarball signature (cosign keyless + sha256sum)

The release pipeline signs `checksums.txt` via cosign keyless and
records the signing event in the [public Rekor transparency log](https://search.sigstore.dev/).
Trust chain: sigstore bundle → checksums file → tarball.

```bash
cd $(mktemp -d)

# Pull checksums + sigstore bundle
for f in checksums.txt checksums.txt.bundle.json; do
  curl -fsSLO https://github.com/gma1k/podtrace/releases/latest/download/$f
done

# Verify the signature was produced by a workflow in gma1k/podtrace
cosign verify-blob \
  --bundle checksums.txt.bundle.json \
  --certificate-identity-regexp 'https://github.com/gma1k/podtrace/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# Verify the tarball matches the (now-trusted) checksum
curl -fsSLO https://github.com/gma1k/podtrace/releases/latest/download/podtrace_linux_amd64.tar.gz
sha256sum -c checksums.txt --ignore-missing
```

If the cosign verify step succeeds, the certificate's `--certificate-identity-regexp`
field proves the tarball was built by a workflow run inside the
`gma1k/podtrace` repository — not by a third party.

### Building from source

If you need a custom build (development, air-gapped clusters, or
unsupported architectures), the rest of this document covers the
toolchain setup and build steps.

## Prerequisites

### System Requirements

- **Linux Kernel**: 5.8+ with BTF support
- **Go**: 1.24+
- **Kubernetes**: Access to a Kubernetes cluster
- **Build Tools**: `clang` and `llc` (LLVM toolchain), **libbpf headers** (e.g. `libbpf-dev` on Debian/Ubuntu)

### Check Kernel Support

```bash
# Check kernel version
uname -r

# Check for BTF support
ls /sys/kernel/btf/vmlinux
```

### Check Go Version

```bash
go version
```

If you need to upgrade Go:

```bash
wget -q https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

## Building from Source

### 1. Clone the Repository

```bash
git clone https://github.com/gma1k/podtrace.git
cd podtrace
```

### 2. Install Dependencies

**System packages (Debian/Ubuntu):**

```bash
sudo apt update
sudo apt install -y clang llvm build-essential libbpf-dev
```

**Go modules:**

```bash
make deps
```

This downloads Go modules and tidies dependencies.

### 3. Build

```bash
# Build eBPF program and Go binary
make build
```

This will:
- Compile the eBPF program (`bpf/podtrace.bpf.c`) to a per-arch object at
  `internal/ebpf/embedded/podtrace.<arch>.bpf.o` (e.g.
  `internal/ebpf/embedded/podtrace.amd64.bpf.o`)
- Build the Go binary to `bin/podtrace`, embedding the per-arch BPF object
  via the `embed_bpf` build tag

### 4. Set Capabilities (Optional)

To run without `sudo`, set the required capabilities:

```bash
# Build and set capabilities in one step
make build-setup

# Or manually
sudo ./scripts/setup-capabilities.sh
```

The script sets:
- `CAP_SYS_ADMIN`: Required for eBPF operations
- `CAP_BPF`: Required for loading eBPF programs (kernel 5.8+)

## Verification

Test the build:

```bash
./bin/podtrace --help
```

You should see usage information.

## Troubleshooting

### Build Errors

**Error: "bpf/bpf_helpers.h file not found" (or similar libbpf header)**
- Install libbpf headers: `sudo apt install libbpf-dev` (Debian/Ubuntu). The Makefile adds `/usr/include` so that `<bpf/bpf_helpers.h>` is found; you can override with `make LIBBPF_INCLUDE=/path/to/include` if your headers are elsewhere.

**Error: "failed to load eBPF program"**
- Ensure kernel version is 5.8+
- Check BTF support: `ls /sys/kernel/btf/vmlinux`
- Verify clang is installed: `clang --version`

**Error: "Go version too old"**
- Upgrade Go to 1.24+ (or 1.21+ with GOTOOLCHAIN=auto)
- The Makefile will show upgrade instructions

**Error: "permission denied" when attaching probes**
- Run with `sudo` or set capabilities
- Check capabilities: `getcap bin/podtrace`

### Runtime Errors

**Error: "failed to resolve pod"**
- Ensure `kubectl` is configured correctly
- Check Kubernetes API access
- Verify pod name and namespace are correct

**Error: "cgroup path not found"**
- Ensure the pod is running
- Check container runtime (Docker, containerd, CRI-O)
- Verify cgroup v2 support
- **Kubelet with `--cgroup-driver=systemd` (e.g. Ubuntu/Debian):** Podtrace automatically looks for container cgroups under both the default cgroup root and `/sys/fs/cgroup/systemd/`. No configuration is required. If you use a custom cgroup root via `PODTRACE_CGROUP_BASE`, ensure it is the host’s cgroup root (e.g. when running in a DaemonSet, mount the host’s `/sys/fs/cgroup` and set `PODTRACE_CGROUP_BASE` to that mount).

**Error: "DNS tracking unavailable"**
- This is a warning, not an error
- DNS tracking requires libc to be found
- The tool will work without DNS tracking

**File Path Resolution Issues:**
- If paths show as `ino:DEV/INO` instead of actual paths, this means inode extraction returned 0
- This can happen if using the placeholder `vmlinux.h` instead of a full version generated from BTF
- To enable full path resolution, generate a complete `vmlinux.h`:
  ```bash
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
  make build
  ```
- Path tracking still works via `open()` events even without inode extraction
- **Note:** The repository includes a minimal placeholder `vmlinux.h` for basic compilation. For full CO-RE support, generate it from BTF as shown above.

## Running in Kubernetes

### As a DaemonSet (recommended)

When Podtrace runs **inside a container** (DaemonSet or Job), it must see the **host’s** cgroup tree, process tree, and (for CRI-based resolution) the container runtime socket. Otherwise you get “no events collected” because:

1. **Cgroup resolution** uses `PODTRACE_CGROUP_BASE` (default `/sys/fs/cgroup`). In a container that is the **container’s** cgroup, not the target pod’s, so the target pod’s cgroup path does not exist and resolution can fail or be wrong.
2. **Event filtering** either uses a kernel cgroup ID (derived from the cgroup path) or a userspace check that reads `/proc/<pid>/cgroup` via `PODTRACE_PROC_BASE`. In a container, default `/proc` is the **container’s** `/proc`; PIDs from the target pod are not visible there, so every event is filtered out and no events are collected.
3. **CRI resolution** (containerd/crio) looks for sockets under `/run/containerd/containerd.sock` etc.; those exist on the host, not in the container, unless you mount and set `PODTRACE_CRI_ENDPOINT`.

Use the following pattern so the DaemonSet pod sees the host’s cgroups, proc, and (optionally) CRI socket, and point Podtrace at them with environment variables:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: podtrace
spec:
  selector:
    matchLabels:
      app: podtrace
  template:
    metadata:
      labels:
        app: podtrace
    spec:
      hostPID: true          # optional but recommended so PIDs match host
      hostNetwork: false     # set true only if you need it
      containers:
      - name: podtrace
        image: your-registry/podtrace:latest
        command: ["/bin/sh", "-c"]
        args:
        - |
          # Example: trace a specific pod for 30s then exit
          ./podtrace -n default my-app-pod --diagnose 30s
          # Or keep running and trace interactively (depends on your entrypoint)
          exec ./podtrace -n default my-app-pod
        env:
        # Point at host mount paths so resolution and filtering see the target pod
        - name: PODTRACE_CGROUP_BASE
          value: /host/sys/fs/cgroup
        - name: PODTRACE_PROC_BASE
          value: /host/proc
        # If you use CRI for pod→cgroup resolution, mount runtime socket and set:
        # - name: PODTRACE_CRI_ENDPOINT
        #   value: unix:///host/run/containerd/containerd.sock
        securityContext:
          capabilities:
            add:
            - SYS_ADMIN
            - BPF
          privileged: false
        volumeMounts:
        - name: host-cgroup
          mountPath: /host/sys/fs/cgroup
          readOnly: true
        - name: host-proc
          mountPath: /host/proc
          readOnly: true
        # Optional: for CRI resolution (containerd example)
        # - name: host-run
        #   mountPath: /host/run
        #   readOnly: true
      volumes:
      - name: host-cgroup
        hostPath:
          path: /sys/fs/cgroup
          type: Directory
      - name: host-proc
        hostPath:
          path: /proc
          type: Directory
      # - name: host-run
      #   hostPath:
      #     path: /run
      #     type: Directory
```

- **PODTRACE_CGROUP_BASE**: Must be the **host** cgroup root (e.g. `/host/sys/fs/cgroup`). Required so that pod→cgroup resolution finds the target pod’s cgroup and (on cgroup v2) so the tracer can set the in-kernel cgroup filter.
- **PODTRACE_PROC_BASE**: Must be the **host** `/proc` (e.g. `/host/proc`). Required for userspace cgroup filtering (cgroup v1 or when kernel cgroup ID is not used) so that `/proc/<pid>/cgroup` exists for the target pod’s PIDs.
- **PODTRACE_CRI_ENDPOINT**: Set to the path where you mount the host’s runtime socket (e.g. `unix:///host/run/containerd/containerd.sock`) if you want CRI-based resolution. Otherwise resolution falls back to scanning the host cgroup and proc (which only works if `PODTRACE_CGROUP_BASE` and `PODTRACE_PROC_BASE` point at the host).

### As a Pod (simple example)

You can also run Podtrace as a single Pod with the same host mounts and env vars as above:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: podtrace
spec:
  containers:
  - name: podtrace
    image: your-registry/podtrace:latest
    env:
    - name: PODTRACE_CGROUP_BASE
      value: /host/sys/fs/cgroup
    - name: PODTRACE_PROC_BASE
      value: /host/proc
    securityContext:
      capabilities:
        add:
        - SYS_ADMIN
        - BPF
    volumeMounts:
    - name: host-cgroup
      mountPath: /host/sys/fs/cgroup
      readOnly: true
    - name: host-proc
      mountPath: /host/proc
      readOnly: true
  volumes:
  - name: host-cgroup
    hostPath:
      path: /sys/fs/cgroup
      type: Directory
  - name: host-proc
    hostPath:
      path: /proc
      type: Directory
```

### Cgroup driver (systemd vs cgroupfs)

Podtrace works with both kubelet cgroup drivers:

- **`--cgroup-driver=cgroupfs`**: Container cgroups are under the default hierarchy (e.g. `/sys/fs/cgroup/kubepods.slice/...`).
- **`--cgroup-driver=systemd`** (common on Ubuntu/Debian): Container cgroups are under the systemd hierarchy (e.g. `/sys/fs/cgroup/systemd/kubepods.slice/...`).

Podtrace tries both the default cgroup root and `/sys/fs/cgroup/systemd` when resolving pod cgroup paths, so no extra configuration is needed for systemd-driven nodes. If your node uses a different layout, set `PODTRACE_CGROUP_BASE` to the host’s cgroup root (and, when running in a container, mount that path into the pod).

### Required Permissions

- **Host cgroup and proc** mounted and `PODTRACE_CGROUP_BASE` / `PODTRACE_PROC_BASE` set (see above); otherwise you get no events when running in a container.
- Kubernetes API access (for pod resolution).
- eBPF capabilities: `SYS_ADMIN`, `BPF`.

## Operator install via Helm

For the CRD-driven workflows (continuous `PodTrace`, bounded
`PodTraceSession`), install the operator alongside the binary. The
chart ships under `deploy/charts/podtrace/`.

### Quick install

For a public release, prefer the OCI chart (no clone needed):

```bash
helm install podtrace oci://ghcr.io/gma1k/charts/podtrace --version 0.1.0 \
  --namespace podtrace-system --create-namespace \
  --set operator.enabled=true
```

For a custom build of this checkout:

```bash
helm install podtrace deploy/charts/podtrace \
  --namespace podtrace-system \
  --create-namespace \
  --set operator.enabled=true \
  --set image.tag=<version>
```

This single command:

- Renders the four CRDs (`TracerConfig`, `PodTrace`, `PodTraceSession`, `ExporterConfig`).
- Creates `podtrace-system` with PSA `enforce: privileged` (the agent DaemonSet and session Jobs need this; user namespaces stay restricted).
- Deploys the operator (unprivileged, single replica with leader election).
- Installs operator ClusterRole + agent RBAC (cluster-scoped ClusterRole + namespaced Role for bundle reads in `podtrace-system`).
- Renders a `default` `TracerConfig`, which the operator picks up and uses to roll out the `podtrace-agent` DaemonSet on every node.

### Verify

```bash
kubectl -n podtrace-system get deploy,ds,pods
kubectl get tracerconfig default
kubectl -n podtrace-system get pods -l podtrace.io/component=agent -o wide
```

You should see the operator Deployment Ready, the DaemonSet with one
pod per node, and `tracerconfig/default` present.

### Common overrides

```bash
# Restrict the agent to nodes labeled podtrace.io/enabled=true
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values \
  --set 'agent.nodeSelector.podtrace\.io/enabled=true'

# Bump per-agent event buffer
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values --set agent.eventBufferSize=50000

# Enable Prometheus monitoring (no-op without prometheus-operator)
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.podMonitor.enabled=true

# Disable the chart-rendered TracerConfig (you author your own)
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values --set tracerConfig.create=false
```

### Webhook TLS

Validating webhooks require TLS. The chart's default
(`webhook.certSource=cert-manager`) renders a `Certificate` that
issues serving certs and annotates the `ValidatingWebhookConfiguration`
with `cert-manager.io/inject-ca-from`. Requires cert-manager already
installed.

For air-gapped clusters without cert-manager, switch to
`webhook.certSource=self-signed` and supply `webhook.caBundle` /
`webhook.tls` directly.

### kind quick start

On a kind cluster, mark the test image as locally loaded so kubelet
doesn't try to pull from a registry:

```bash
make docker-build IMAGE_TAG=dev
kind load docker-image ghcr.io/gma1k/podtrace:dev

helm install podtrace deploy/charts/podtrace \
  --namespace podtrace-system \
  --create-namespace \
  --set operator.enabled=true \
  --set image.repository=ghcr.io/gma1k/podtrace \
  --set image.tag=dev \
  --set image.pullPolicy=Never
```

See [operator.md](operator.md) for the architectural picture and
[crd-podtracesession.md](crd-podtracesession.md) for an end-to-end
trace example after install.
