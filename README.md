<p align="center">
  <a href="https://github.com/gma1k/podtrace">
    <img src="https://github.com/gma1k/podtrace/blob/main/assets/podtrace-logo.png" width="420" alt="podtrace logo"/>
  </a>
</p>

A simple but powerful eBPF-based diagnostic tool for Kubernetes applications.

## Overview

`podtrace` attaches eBPF programs to a single Kubernetes pod's container and prints high-level, human-readable events that help diagnose application issues.

## Features

- **Network Connection Monitoring**: Tracks TCP IPv4/IPv6 connection latency and errors
- **TCP RTT Analysis**: Detects RTT spikes and retry patterns
- **File System Monitoring**: Tracks read, write, and fsync operations with latency analysis
- **CPU/Scheduling Tracking**: Monitors thread blocking and CPU scheduling events
- **DNS Tracking**: Monitors DNS lookups
- **CPU Usage per Process**: Shows CPU consumption by process
- **Process Activity Analysis**: Shows which processes are generating events
- **Diagnose Mode**: Collects events for a specified duration and generates a comprehensive summary report

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
- **TCP Statistics**: RTT analysis, spikes detection, send/receive operations
- **Connection Statistics**: IPv4/IPv6 connection latency, failures, error breakdown, top targets
- **File System Statistics**: Read, write, and fsync operation latency, slow operations
- **CPU Statistics**: Thread blocking times and scheduling events
- **CPU Usage by Process**: CPU percentage per process
- **Process Activity**: Top active processes by event count
- **Activity Timeline**: Event distribution over time
- **Activity Bursts**: Detection of burst periods
- **Connection Patterns**: Analysis of connection behavior
- **Network I/O Patterns**: Send/receive ratios and throughput analysis
- **Potential Issues**: Automatic detection of high error rates and performance problems

## Running without sudo

After building, set capabilities to run without sudo:

```bash
sudo ./scripts/setup-capabilities.sh
```
