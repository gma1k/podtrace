# Performance Profiling Guide

Podtrace integrates on-demand CPU and memory profiling with eBPF event correlation, letting you pinpoint the exact goroutines and call stacks active during slow or anomalous events — without modifying your application.

## Overview

The profiling system combines three data sources:

- **pprof profiles** fetched from the target pod's HTTP pprof endpoint (heap, goroutine, CPU)
- **BPF `SchedSwitch` events** that record which goroutines were scheduled in/out during slow periods
- **Wall-clock alignment** via a monotonic offset, so kernel timestamps map precisely to wall time

These are correlated by `internal/profiling/correlator.go` to produce `CorrelatedResult` structs that surface the exact stacks active during high-latency events.

## Quick Start

```bash
# Enable profiling
./bin/podtrace -n production my-pod --profiling

# Or via environment variable
export PODTRACE_PROFILING_ENABLED=true
./bin/podtrace -n production my-pod
```

When `--profiling` is set, Podtrace's own process pprof endpoint is also auto-enabled at the standard `/debug/pprof/` path.

## Management API Endpoints

Profiling is controlled through the Podtrace management HTTP server (`PODTRACE_MANAGEMENT_PORT`):

| Endpoint | Method | Description |
|---|---|---|
| `/profile/start` | POST | Trigger an immediate profiling capture |
| `/profile/status` | GET | Check whether a capture is in progress or complete |
| `/profile/result` | GET | Retrieve the latest correlated profiling result |

```bash
# Trigger a profiling capture
curl -X POST http://localhost:<MANAGEMENT_PORT>/profile/start

# Check status
curl http://localhost:<MANAGEMENT_PORT>/profile/status

# Retrieve results
curl http://localhost:<MANAGEMENT_PORT>/profile/result
```

## Auto-trigger

Profiling can also fire automatically when event latency exceeds configured thresholds — no manual intervention needed. When the handler detects a slow event, it triggers a capture and correlates the result against the active BPF `SchedSwitch` stacks from that time window.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PODTRACE_PROFILING_ENABLED` | `false` | Enable profiling (equivalent to `--profiling` flag) |
| `PODTRACE_MANAGEMENT_PORT` | `9090` | Port for the management HTTP server |

## Report Integration

Profiling correlation results are automatically appended to:

- **Diagnose mode reports** (`--diagnose <duration>`) — a dedicated profiling section summarises correlated stacks alongside the other diagnostic sections
- **Normal mode output** — slow-event correlations are included in the real-time event stream

## Architecture

```
BPF SchedSwitch events
        │
        ▼
internal/profiling/clock.go       ← ktime → wall-clock offset
        │
        ▼
internal/profiling/correlator.go  ← correlates stacks with slow events
        │
internal/profiling/profiler.go    ← discovers + fetches pprof from pod
        │
        ▼
internal/profiling/handler.go     ← fan-out consumer, auto-trigger, HTTP endpoints
```
