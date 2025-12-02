# Installation

## Prerequisites

### System Requirements

- **Linux Kernel**: 5.8+ with BTF support
- **Go**: 1.24+
- **Kubernetes**: Access to a Kubernetes cluster
- **Build Tools**: `clang` and `llc` (LLVM toolchain)

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

**Optional: Enable File Path Tracking**

File path tracking is disabled by default because it requires the `bpf_d_path` helper function (kernel 5.6+). If your kernel supports it, you can enable it:

```bash
make ENABLE_FILE_PATH_TRACKING=1

# Or set it permanently in Makefile
# Change: ENABLE_FILE_PATH_TRACKING ?= 0
# To:     ENABLE_FILE_PATH_TRACKING ?= 1
```

**Note**: If you enable file path tracking but your kernel doesn't support `bpf_d_path`, podtrace will fail to load with an error about "unknown func bpf_d_path". In this case, rebuild with `ENABLE_FILE_PATH_TRACKING=0` (the default).

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

**Error: "DNS tracking unavailable"**
- This is a warning, not an error
- DNS tracking requires libc to be found
- The tool will work without DNS tracking

**Error: "unknown func bpf_d_path"**
- This occurs when file path tracking is enabled but the kernel doesn't support `bpf_d_path`
- Rebuild with `ENABLE_FILE_PATH_TRACKING=0` (the default)
- File path tracking requires kernel 5.6+ with `bpf_d_path` helper support

## Running in Kubernetes

### As a Pod

You can run podtrace as a DaemonSet or Job in your cluster:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: podtrace
spec:
  containers:
  - name: podtrace
    image: your-registry/podtrace:latest
    securityContext:
      capabilities:
        add:
        - SYS_ADMIN
        - BPF
    volumeMounts:
    - name: sys
      mountPath: /sys
    - name: proc
      mountPath: /proc
  volumes:
  - name: sys
    hostPath:
      path: /sys
  - name: proc
    hostPath:
      path: /proc
```

### Required Permissions

- Access to `/sys/fs/cgroup` (for cgroup filtering)
- Access to `/proc` (for process information)
- Kubernetes API access (for pod resolution)
- eBPF capabilities (SYS_ADMIN, BPF)