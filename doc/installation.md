# Installation

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
git clone https://github.com/podtrace/podtrace.git
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
- Compile the eBPF program (`bpf/podtrace.bpf.c`) to `bpf/podtrace.bpf.o`
- Build the Go binary to `bin/podtrace`

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
