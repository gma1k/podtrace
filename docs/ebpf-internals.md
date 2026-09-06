# eBPF Internals

## Overview

Podtrace uses eBPF (extended Berkeley Packet Filter) to trace system calls and kernel events at the kernel level, providing low-overhead observability without modifying application code.

## eBPF Program Structure

### Maps

eBPF maps are used for communication between kernel and user space:

1. **Ring Buffer (`events`)**
   - Type: `BPF_MAP_TYPE_RINGBUF`
   - Size: 2 MB (2048 KB)
   - Purpose: Transfer event data from kernel to user space
   - One-way: Kernel writes, user space reads

2. **Start Times (`start_times`)**
   - Type: `BPF_MAP_TYPE_HASH`
   - Size: 1024 entries
   - Purpose: Store timestamps for latency calculation
   - Key: `(pid << 32) | tid` (process and thread ID)
   - Value: Start timestamp in nanoseconds

3. **DNS Targets (`dns_targets`)**
   - Type: `BPF_MAP_TYPE_HASH`
   - Size: 1024 entries
   - Purpose: Store DNS query targets
   - Key: `(pid << 32) | tid`
   - Value: DNS target string (max 128 chars)

4. **Socket Connections (`socket_conns`)**
   - Type: `BPF_MAP_TYPE_HASH`
   - Size: 1024 entries
   - Purpose: Store socket connection information
   - Key: `(pid << 32) | tid`
   - Value: Connection string (IP:port or URL)

5. **File Inodes (`file_inodes`)**
   - Type: `BPF_MAP_TYPE_HASH`
   - Size: 1024 entries
   - Purpose: Store inode+device ID for filesystem operations
   - Key: `(pid << 32) | tid`
   - Value: `(device_id << 32) | inode_number` (packed as u64)
   - Note: Path resolution happens in userspace by correlating with `open()` events

6. **TCP Sockets (`tcp_sockets`)**
   - Type: `BPF_MAP_TYPE_HASH`
   - Size: 1024 entries
   - Purpose: Store TCP socket information
   - Key: `(pid << 32) | tid`
   - Value: Socket identifier

7. **Stack Traces (`stack_traces`)**
   - Type: `BPF_MAP_TYPE_HASH`
   - Size: 2048 entries
   - Purpose: Store user-space stack traces
   - Key: Unique stack trace identifier
   - Value: Stack trace structure with instruction pointers

8. **Event Buffer (`event_buf`)**
   - Type: `BPF_MAP_TYPE_ARRAY`
   - Size: 1 entry (per-CPU)
   - Purpose: Temporary storage for event structures (avoids stack overflow)
   - Key: `u32` (always 0)
   - Value: `struct event`

9. **Stack Buffer (`stack_buf`)**
   - Type: `BPF_MAP_TYPE_ARRAY`
   - Size: 1 entry (per-CPU)
   - Purpose: Temporary storage for stack traces (avoids stack overflow)
   - Key: `u32` (always 0)
   - Value: `struct stack_trace_t`

10. **Lock Targets (`lock_targets`)**
    - Type: `BPF_MAP_TYPE_HASH`
    - Size: 1024 entries
    - Purpose: Store lock identifiers for contention tracking
    - Key: `(pid << 32) | tid`
    - Value: Lock identifier string

11. **Database Queries (`db_queries`)**
    - Type: `BPF_MAP_TYPE_HASH`
    - Size: 1024 entries
    - Purpose: Store sanitized database query patterns
    - Key: `(pid << 32) | tid`
    - Value: Query pattern string (first token only, sanitized)

12. **Syscall Paths (`syscall_paths`)**
    - Type: `BPF_MAP_TYPE_HASH`
    - Size: 1024 entries
    - Purpose: Store file paths for syscall operations (exec, open)
    - Key: `(pid << 32) | tid`
    - Value: File path string (max 128 chars)

## Event Types

```c
enum event_type {
    EVENT_DNS,            // DNS lookups
    EVENT_CONNECT,        // TCP connections (IPv4/IPv6)
    EVENT_TCP_SEND,       // TCP send operations
    EVENT_TCP_RECV,       // TCP receive operations
    EVENT_WRITE,          // File write operations
    EVENT_READ,           // File read operations
    EVENT_FSYNC,          // File sync operations
    EVENT_SCHED_SWITCH,   // CPU scheduling events
    EVENT_TCP_STATE,      // TCP connection state transitions
    EVENT_PAGE_FAULT,     // Page fault events
    EVENT_OOM_KILL,       // Out-of-memory kill events
    EVENT_UDP_SEND,       // UDP send operations
    EVENT_UDP_RECV,       // UDP receive operations
    EVENT_HTTP_REQ,       // HTTP request events
    EVENT_HTTP_RESP,      // HTTP response events
    EVENT_LOCK_CONTENTION, // Lock contention events
    EVENT_TCP_RETRANS,    // TCP retransmission events
    EVENT_NET_DEV_ERROR,  // Network device error events
    EVENT_DB_QUERY,       // Database query events
    EVENT_EXEC,           // Process execution (execve)
    EVENT_FORK,           // Process/thread creation
    EVENT_OPEN,           // File open operations
    EVENT_CLOSE           // File close operations
};
```

## Event Structure

```c
struct event {
    u64 timestamp;      // Event timestamp (nanoseconds)
    u32 pid;            // Process ID
    u32 type;           // Event type
    u64 latency_ns;     // Operation latency (nanoseconds)
    s32 error;          // Error code (0 = success)
    u64 bytes;          // Bytes transferred (for I/O operations)
    u32 tcp_state;      // TCP state (for TCP state events)
    u64 stack_key;      // Reference to stack trace in stack_traces map
    char target[128];   // Target (IP:port, hostname, filename, query pattern)
    char details[128];  // Additional details
};
```

## Tracing Mechanisms

### Kprobes

Kprobes attach to kernel functions:

**Network Tracing:**
- `tcp_v4_connect` / `tcp_v6_connect`: Entry and return probes
  - Entry: Record start time, extract destination IP:port
  - Return: Calculate latency, record error code

- `tcp_sendmsg` / `tcp_recvmsg`: Entry and return probes
  - Entry: Record start time
  - Return: Calculate RTT/latency

**File System Tracing:**
- `vfs_read` / `vfs_write` / `vfs_fsync`: Entry and return probes
  - Entry: Record start time, extract inode+device ID from `struct file*`
  - Return: Calculate latency, encode inode as `ino:DEV/INO` string
- `do_sys_openat2`: Entry and return probes
  - Entry: Record start time, capture file path from function parameter
  - Return: Calculate latency, emit `EventOpen` with full path
- Path Resolution: Userspace correlates `open()` paths with `read()`/`write()` by inode

### Uprobes

Uprobes attach to user-space functions:

**DNS Tracing:**
- `getaddrinfo` (libc): Entry and return probes
  - Entry: Extract hostname from arguments, store in map
  - Return: Calculate latency, record error

### Tracepoints

Tracepoints are kernel instrumentation points:

**CPU Scheduling:**
- `sched_switch`: Triggered on context switches
  - Records thread blocking time
  - Tracks CPU scheduling events

## Stack Traces

Podtrace captures user-space stack traces for slow operations to help identify exact code paths causing performance issues.

### Stack Trace Capture

Stack traces are captured using the `bpf_get_stack()` helper with `BPF_F_USER_STACK` flag:

```c
static inline void capture_user_stack(void *ctx, u32 pid, u32 tid, struct event *e) {
    u32 zero = 0;
    struct stack_trace_t *trace = bpf_map_lookup_elem(&stack_buf, &zero);
    if (!trace) {
        e->stack_key = 0;
        return;
    }
    trace->nr = 0;
    int sz = bpf_get_stack(ctx, trace->ips, sizeof(trace->ips), BPF_F_USER_STACK);
    if (sz <= 0) {
        e->stack_key = 0;
        return;
    }
    trace->nr = sz / sizeof(u64);
    u64 key = build_stack_key(pid, tid, e->timestamp);
    bpf_map_update_elem(&stack_traces, &key, trace, BPF_ANY);
    e->stack_key = key;
}
```

### Stack Trace Storage

- **Temporary Buffer**: `stack_buf` (ARRAY map) stores stack trace during capture to avoid stack overflow
- **Persistent Storage**: `stack_traces` (HASH map) stores completed stack traces
- **Event Reference**: Each event contains a `stack_key` that references its stack trace
- **User Space Resolution**: Stack traces are resolved to symbols using `addr2line` in user space

### When Stack Traces Are Captured

Stack traces are captured for operations exceeding performance thresholds:
- Slow file I/O operations (read/write/fsync > 1ms)
- Slow DNS lookups
- Slow network operations (TCP send/receive with high latency)
- Lock contention events (futex/pthread mutex waits > 1ms)
- Process execution (execve)
- Database query operations
- Network errors and TCP retransmissions

### Stack Trace Structure

```c
struct stack_trace_t {
    u64 ips[MAX_STACK_DEPTH];
    u32 nr;                     // Number of frames captured
};
```

## Latency Calculation

Latency is calculated using the start time stored in the hash map:

```c
static inline u64 calc_latency(u64 start) {
    u64 now = bpf_ktime_get_ns();
    return now > start ? now - start : 0;
}
```

1. Entry probe: Store `bpf_ktime_get_ns()` in map with key `(pid << 32) | tid`
2. Return probe: Read start time from map, calculate `now - start`
3. Clean up: Remove entry from map

## IP Address Formatting

IPv4 addresses are formatted as `A.B.C.D:PORT`:

```c
static inline void format_ip_port(u32 ip, u16 port, char *buf) {
    // Extracts bytes from 32-bit IP
    // Formats as decimal string
    // Appends port number
}
```

## Error Handling

- Error codes are captured from kernel return values
- Negative values indicate errors
- `-11` (EAGAIN) is treated as non-fatal for TCP operations
- Error codes are passed to user space for analysis

## Performance Considerations

### Ring Buffer

- Lockless, high-performance data structure
- 2 MB buffer handles high event rates
- User space must read promptly to avoid drops
- Larger buffer reduces event loss during high-throughput scenarios

### Hash Maps

- Limited to 1024 entries to control memory usage
- LRU-like behavior: old entries are overwritten
- Key collision handling: `(pid << 32) | tid` ensures uniqueness

### Probe Overhead

- Minimal overhead: simple timestamp and map operations
- No blocking operations in eBPF programs
- Fast path: most operations complete in microseconds

## Compilation

The eBPF program is compiled with:

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -mcpu=v3 \
      -Ibpf -I. -c bpf/podtrace.bpf.c -o internal/ebpf/embedded/podtrace.amd64.bpf.o
```

Note: The eBPF code is now modular. `podtrace.bpf.c` includes all modules:
- `network.c` - Network probes (TCP, UDP, DNS, HTTP, retransmissions, errors)
- `filesystem.c` - Filesystem probes
- `cpu.c` - CPU/scheduling probes and lock contention
- `memory.c` - Memory probes
- `syscalls.c` - System call probes (exec, fork, open, close)

The header files (`common.h`, `maps.h`, `events.h`, `helpers.h`) provide shared definitions.

Flags:
- `-O2`: Optimize for performance
- `-g`: Include debug information
- `-target bpf`: Compile for eBPF target
- `-D__TARGET_ARCH_x86`: Define target architecture
- `-mcpu=v3`: Use BPF v3 instruction set

## Kernel-side metric aggregation

`bpf/agg.h` folds metric observations into a BPF map instead of shipping one
ring-buffer record per observation, so the continuous metrics plane costs
O(series) rather than O(events). The probes call `agg_from_event()` beside
each `bpf_ringbuf_output()`, and the agent drains the map on an interval.

### Bucket indices are map keys, not offsets

The obvious way to build a histogram in BPF is an array of counters indexed by
bucket, which forces every index to be a compile-time-constant-masked offset
into a map value, the constraint this codebase has hit before. This design
sidesteps it: the bucket is part of the map **key**, so there is no
variable-offset write to mask, and the accumulators live in the map value
rather than on the stack.

### The index is Prometheus schema 3

`agg_bucket()` computes `floor(log2(v) * 8)`: the Prometheus native-histogram
schema a bucket factor of 1.1 resolves to. It is a branchless MSB search
(no loop, so the verifier sees straight-line code) plus seven comparisons
against the normalized sub-boundaries.

Those boundaries are `2^(k/8) * 2^32` for k=1..7 and must be exact. Hand-written
constants were wrong on the first attempt; they are now generated and verified
against Prometheus's own formula — `SearchFloat64s(bounds, frac) + (exp-1)*8`
from `client_golang`, across every value from 1 to 100000 plus every
power-of-two boundary. `kernelagg.BucketIndex()` is the Go mirror.

### Struct layout must be spelled out

`struct agg_key` ends with explicit `u8 pad[6]`. The struct would be padded to
its `u64` alignment anyway, but Go's `encoding/binary` adds no implicit
trailing padding, so an implicitly-padded struct decodes short. That failure
mode is quiet in the worst way, a misread key attributes metrics to the wrong
workload — so a test asserts `binary.Size(Key{}) == 24`.

### Reserved records must be released

The ring-buffer bypass skips `bpf_ringbuf_output()` for anything the map
absorbed. Where a probe uses the reserve/submit form instead, `bpf/dns.c` —
the reservation must be **discarded**, not simply skipped, or it leaks and the
ring wedges.

### Arch coverage

Both the BTF and stub builds produce the full program set on amd64 and
arm64. The kernel verifier has been exercised on amd64; arm64 is
compile-verified only, since it needs an arm64 kernel to load against.

## Verification

The kernel verifies eBPF programs before loading:

- **Safety checks**: No infinite loops, bounded memory access
- **Type checking**: Map access validation
- **Resource limits**: Program size, complexity limits
- **Helper functions**: Only allowed kernel helpers

## User Space Integration

The Go application:

1. **Loads** the compiled eBPF object file
2. **Attaches** programs to kernel functions
3. **Reads** events from ring buffer
4. **Filters** events by cgroup (user space)
5. **Processes** events and generates reports

## Limitations

- **Kernel version**: Requires 5.8+ for ring buffer support
- **BTF**: Requires BTF for CO-RE (Compile Once - Run Everywhere)
- **Permissions**: Requires CAP_SYS_ADMIN or CAP_BPF
- **Map size**: Limited by kernel configuration
- **Probe availability**: Some probes may not be available on all systems

## Debugging

To debug eBPF programs:

1. **Check compilation**: Ensure no compilation errors
2. **Verify loading**: Check kernel logs (`dmesg`)
3. **Test probes**: Verify probes attach successfully
4. **Monitor events**: Check ring buffer for events
5. **Kernel logs**: Look for eBPF-related errors

Common issues:
- Probe attachment failures (permissions, missing symbols)
- Map access errors (wrong key/value types)
- Ring buffer drops (user space not reading fast enough)