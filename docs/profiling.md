# Performance Profiling Guide

Podtrace integrates on-demand CPU and memory profiling with eBPF event correlation, letting you pinpoint the exact goroutines and call stacks active during slow or anomalous events — without modifying your application.

There are two profilers, and they answer different questions.

| | Continuous profiling | Session profiling |
|---|---|---|
| Answers | what has this workload been spending CPU on | what was running during *these* slow requests |
| Runs | always, in the agent | inside a session you start |
| Needs | nothing from the workload | a pprof endpoint and a Go runtime |
| Works for | any language | Go |
| Read at | the agent's `/profile` | the diagnose report |

Continuous profiling is the one that makes podtrace an APM rather than a
debugger you point at a problem after someone reports it. The rest of this
document is the session profiler; continuous profiling is immediately below.

## Continuous profiling

On by default, and there is nothing to add to the workload. Turn it off in
the chart, or on the TracerConfig directly:

```yaml
agent:
  continuousProfiling: false
```

```yaml
apiVersion: podtrace.io/v1alpha1
kind: TracerConfig
spec:
  agent:
    continuousProfiling: false
```

Setting `PODTRACE_CONTINUOUS_PROFILING_ENABLED` on the DaemonSet by hand does
not work: the operator owns the agent's environment and reconciles hand-edits
away on its next pass. The CRD field is the only durable switch.

Every `sched_switch` already carries the user-space stack of the task going
off-CPU, so the samples exist whether or not anyone is looking. The agent folds
them into a rolling per-workload count of hot instruction pointers and serves
the result as JSON on `/profile`, alongside `/metrics`:

```bash
# The agent image ships no shell tools, so read it through a port-forward.
# Pick the agent on the node whose workloads you want.
kubectl -n podtrace-system port-forward pod/<agent-pod> 9090:9090 &
curl -s localhost:9090/profile
```

```json
{
  "profiles": [
    {
      "namespace": "shop",
      "workload": "checkout",
      "samples": 18432,
      "frames": [
        {"Frame": "encoding/json.(*decodeState).object", "Count": 4211},
        {"Frame": "runtime.mallocgc", "Count": 2980}
      ],
      "schedulerFrames": 36864
    }
  ],
  "droppedSamples": 0
}
```

Three properties are worth knowing, because they are what keep it affordable:

**Addresses are counted raw and symbolised only at snapshot time.** Resolving
one frame means opening the target's executable and reading its symbol table.
Doing that per sample at `sched_switch` rates would cost more than the workload
being profiled. The event path does a map increment; only the frames that reach
a snapshot are ever named, at most 64 of them. For a Go 1.18+ binary the agent
keeps only `.gopclntab`'s function table in memory, 8 bytes per function, and
reads each name from the file when it is asked for; the index is shared by
every snapshot, so a scrape does not parse the binary again.

**Go scheduler frames are hidden, and counted.** Every `sched_switch` stack
passes through the scheduler on its way off the CPU, so `runtime.schedule`,
`runtime.park_m`, `runtime.mcall` and `runtime.goexit` are in every sample and
would lead every profile. They are left out of `frames` and their hits are
reported in `schedulerFrames`. Blocking points such as `runtime.chanrecv`,
`runtime.selectgo` and `sync.runtime_Semacquire` are kept, because they say
what the code is waiting on. The same filter applies to the diagnose report's
hot frames, which prints how many it hid.

**Counts age out.** Samples live in two half-windows that rotate every five
minutes, so a snapshot reflects the last five to ten minutes rather than
everything since the agent started. A workload that was hot an hour ago should
not still look hot.

**It is bounded in both directions.** At most 200 workloads per node and 4096
distinct addresses per workload. Anything refused is counted in
`droppedSamples`, so a node profiling only part of what it sees says so rather
than quietly under-reporting.

### Why it is not a Prometheus metric

A function name is an unbounded label. This plane has already had one
production incident from putting an unbounded label on a metric, and a stack
shape is a worse offender than a process name. The snapshot endpoint carries
the same information without letting a workload's call graph consume the series
budget. If you want profiles in long-term storage, scrape `/profile` on your
own interval and keep them where profiles belong.

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
