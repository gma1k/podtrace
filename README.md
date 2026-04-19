<p align="center">
  <a href="https://github.com/gma1k/podtrace">
    <img src="https://github.com/gma1k/podtrace/blob/main/assets/podtrace-logo.png" width="420" alt="Podtrace logo"/>
  </a>
</p>

A lightweight yet powerful eBPF-driven diagnostic tool for Kubernetes applications. Podtrace delivers full-stack observability from kernel events to application-layer behavior, all activated on demand, with no prior configuration or instrumentation. With a single command, it uncovers insights across the entire lifecycle of a pod, including network flows, TCP/UDP performance, file system activity, memory behavior, latency patterns, system calls, and high-level application events such as HTTP, DNS, and database queries.

## Overview

Podtrace attaches eBPF programs directly to the container, allowing it to observe real behavior as it happens at runtime. It automatically correlates low-level kernel activity with high-level application operations, surfacing clear, human-readable diagnostic events that reveal what the pod is experiencing internally.

Instead of assembling data from multiple systems or modifying application code, Podtrace provides deep operational visibility in one place, enabling you to understand:

- Why a service is slow  
- Where latency originates  
- How network and I/O resources are being used  
- Which operations block or fail  
- How requests flow through the application  
- What happens inside the pod during incidents  

By combining system-level details, application-layer insights, and real-time event correlation, Podtrace acts as a single on-demand observability lens. This makes it uniquely effective for debugging, performance analysis, and production incident response in Kubernetes environments, especially when time, context, or access is limited.


## Documentation

Podtrace documentation is available in the [`doc/`](doc/) directory.

## Features

### Network Tracing
- **TCP Connection Monitoring**: Tracks TCP IPv4/IPv6 connection latency and errors
- **TCP RTT Analysis**: Detects RTT spikes and retry patterns
- **TCP State Tracking**: Monitors TCP connection state transitions (SYN, ESTABLISHED, FIN, etc.)
- **TCP Retransmission Tracking**: Detects TCP retransmissions for network quality diagnostics
- **Network Device Errors**: Monitors network interface errors and packet drops
- **UDP Network Tracing**: Tracks UDP send/receive operations with latency and bandwidth metrics
- **I/O Bandwidth Tracking**: Monitors bytes transferred for TCP/UDP send/receive operations

### File System Monitoring
- **File Operations**: Tracks read, write, and fsync operations with latency analysis
- **File Path Tracking**: Captures full file paths
- **I/O Bandwidth**: Monitors bytes transferred for file read/write operations
- **Throughput Analysis**: Calculates average throughput and peak transfer rates

### Memory & System Events
- **Page Fault Tracking**: Monitors page faults with error code analysis
- **OOM Kill Detection**: Tracks out-of-memory kills with memory usage details

### Application Layer
- **HTTP Tracing**: HTTP request/response tracking via uprobes
- **DNS Tracking**: Monitors DNS lookups with latency and error tracking
- **Database Query Tracing**: Tracks PostgreSQL and MySQL query execution with pattern extraction and latency analysis
- **TLS/SSL Handshake Tracking**: Track TLS handshake latency, errors and failures
- **Connection Pool Monitoring**: Tracks connection pool usage, monitors pool exhaustion, and tracks connection reuse patterns
- **Redis Tracing**: Captures hiredis `redisCommand` / `redisCommandArgv` calls with command name and latency (no application changes required)
- **Memcached Tracing**: Captures libmemcached `get`, `set`, and `delete` operations with key and value size
- **FastCGI / PHP-FPM Tracing**: Tracks FastCGI request URI, method, and end-to-end latency via unix-socket kprobes (BTF-only)
- **gRPC Method Tracing**: Extracts gRPC method paths from HTTP/2 HEADERS frames via a second kprobe on `tcp_sendmsg` (BTF-only)
- **Kafka Tracing**: Tracks librdkafka `rd_kafka_produce` and `rd_kafka_consumer_poll` with topic name, payload size, and latency
- **USDT Auto-Detection**: Scans ELF binaries for `.note.stapsdt` sections and reports available userspace tracepoints
- **Critical Path Reconstruction**: Automatically correlates per-request latency segments by PID and emits a breakdown on HTTP/FastCGI/gRPC response boundaries
- **PII Redaction**: Applies configurable regex rules to scrub passwords, Bearer tokens, email addresses, and credit card numbers from event fields before dispatch

### System Monitoring
- **CPU/Scheduling Tracking**: Monitors thread blocking and CPU scheduling events
- **CPU Usage per Process**: Shows CPU consumption by process
- **Process Activity Analysis**: Shows which processes are generating events
- **Stack Traces for Slow Operations**: Captures user-space stack traces for slow I/O, DNS, CPU blocks, memory faults, and other operations exceeding thresholds
- **Lock Contention Tracking**: Monitors futex and pthread mutex waits with timing and hot lock identification
- **Syscall Tracing**: Tracks process lifecycle via execve, fork/clone, open/openat, and close syscalls with file descriptor leak detection
- **Network Reliability**: Monitors TCP retransmissions and network device errors for network quality diagnostics
- **Database Query Tracing**: Tracks PostgreSQL and MySQL query execution patterns and latency
- **Resource Limit Monitoring**: Monitor resource usage vs limits
- **Error Correlation with Root Cause Analysis**: Correlates errors with operations and Kubernetes context

### Multi-Pod Tracing
- **Dynamic Multi-Pod Targeting**: Trace multiple pods in one run using explicit pod lists, label selectors, or namespace-wide selection
- **Cross-Namespace Support**: Trace pods across namespaces with `--namespaces` and selector-based targeting
- **Live Target Updates**: Automatically refresh target pod/cgroup filters when pods are added, updated, or deleted

### Distributed Tracing
- **Trace Context Extraction**: Automatically extracts trace context from HTTP/HTTP2 headers and gRPC metadata
- **Event Correlation**: Groups events by trace ID to build complete request flows across services
- **Request Flow Graphs**: Builds directed graphs showing service interactions with latency and error metrics
- **Multiple Exporters**: Supports OpenTelemetry (OTLP), Jaeger, Splunk HEC, Datadog, and Zipkin
- **Sampling Support**: Configurable sampling rates to control export volume

### Performance Profiling
- **pprof & perf Integration**: Discovers and fetches heap, goroutine, and CPU profiles from target pod pprof HTTP endpoints
- **On-demand Profiling Triggers**: Activate profiling via the `/profile/start` management endpoint or automatically when slow events exceed configurable thresholds
- **CPU/Memory Profiling Correlation**: Ties BPF `SchedSwitch` stack traces to slow events, surfacing the exact goroutine and CPU stacks active during high-latency periods
- **BPF ktime ↔ Wall-clock Alignment**: Derives a monotonic offset so kernel timestamps map accurately to wall time for precise correlation
- **Profiling Section in Reports**: Correlation results are appended to both diagnose-mode and normal-mode reports

### Diagnostics
- **Diagnose Mode**: Collects events for a specified duration and generates a comprehensive summary report

### Alerting
- **Real-time Alerts**: Sends immediate notifications when fatal, critical, or warning-level issues are detected
- **Multiple Channels**: Supports webhooks, Slack, and Splunk HEC for alert delivery
- **Smart Deduplication**: Prevents alert storms with configurable deduplication windows
- **Rate Limiting**: Configurable rate limits to prevent overwhelming notification systems

## Prerequisites

- Linux kernel 5.8+ with BTF support
- Go 1.24+
- Kubernetes cluster access

## Building

```bash
# Install dependencies
make deps

# Build eBPF program and Go binary
make build

# Build and set capabilities
make build-setup
```

## Usage

### Basic Usage

```bash
# Trace a pod in real-time
./bin/podtrace -n production my-pod

# Run in diagnostic mode
./bin/podtrace -n production my-pod --diagnose 20s
```

### Diagnose Report

The diagnose mode generates a comprehensive report including:

- **Summary Statistics**: Total events, events per second, collection period
- **DNS Statistics**: DNS lookup latency, errors, top targets
- **TCP Statistics**: RTT analysis, spikes detection, send/receive operations, bandwidth metrics (total bytes, average bytes, peak bytes, throughput)
- **UDP Statistics**: Send/receive operations, latency analysis, bandwidth metrics, error tracking
- **Connection Statistics**: IPv4/IPv6 connection latency, failures, error breakdown, top targets
- **TCP Connection State Tracking**: State transition analysis, state distribution, connection lifecycle monitoring
- **File System Statistics**: Read, write, and fsync operation latency, slow operations, bandwidth metrics (total bytes, average bytes, throughput)
- **HTTP Statistics**: Request/response counts, latency analysis, bandwidth metrics, top requested URLs
- **Memory Statistics**: Page fault counts and error codes, OOM kill tracking with memory usage details
- **CPU Statistics**: Thread blocking times and scheduling events
- **CPU Usage by Process**: CPU percentage per process
- **Process Activity**: Top active processes by event count
- **Activity Timeline**: Event distribution over time
- **Activity Bursts**: Detection of burst periods
- **Connection Patterns**: Analysis of connection behavior
- **Network I/O Patterns**: Send/receive ratios and throughput analysis
- **Process and Syscall Activity**: Process execution, fork/clone, file operations, and file descriptor leak detection
- **Stack Traces for Slow Operations**: User-space stack traces for operations exceeding thresholds with symbol resolution
- **Lock Contention Analysis**: Futex and pthread mutex wait times and hot lock identification
- **Network Reliability**: TCP retransmission tracking and network device error monitoring
- **Database Query Performance**: Query pattern analysis and execution latency (PostgreSQL, MySQL)
- **Connection Pool Statistics**: Connection pool usage, acquire/release rates, reuse patterns, and exhaustion events
- **Potential Issues**: Automatic detection of high error rates and performance problems
- **Resource Limit Monitoring**: Monitor resource usage vs limits
- **Error Correlation with Root Cause Analysis**: Correlates errors with operations and Kubernetes context

## Running without sudo

After building, set capabilities to run without sudo:

```bash
sudo ./scripts/setup-capabilities.sh
```

