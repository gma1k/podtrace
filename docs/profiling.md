# Performance Profiling Guide

Podtrace integrates on-demand CPU and memory profiling with eBPF event correlation, letting you pinpoint the exact goroutines and call stacks active during slow or anomalous events — without modifying your application.

There are two profilers, and they answer different questions.

| | Continuous profiling | Session profiling |
|---|---|---|
| Answers | what has this workload been spending CPU on, and where its slowest requests spent theirs | what was running during *these* slow requests |
| Runs | always, in the agent | inside a session you start |
| Needs | nothing from the workload | a pprof endpoint and a Go runtime |
| Works for | any language | Go |
| Read at | `kubectl podtrace status --profile`, or the agent's `/profile` | the diagnose report |

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

### Where the samples come from

The agent attaches a sampler to a cpu-clock perf event on every CPU. It fires
99 times a second per CPU (99 rather than 100, so it does not beat in step with
work on a 10 ms period). Each time it fires on a CPU running a target workload,
it records the user-space stack of the task that was running. A function that
burns CPU is sampled in proportion to the CPU it burns, whether or not it ever
blocks.

The kernel keeps a count per distinct stack, and the agent reads the counts
every five seconds. A busy node crosses into userspace once per distinct stack,
not once per sample.

Where the perf event cannot be opened, the profiler falls back to the stack
every `sched_switch` already carries: the stack of a task going off the CPU.
That stack shows where the task stopped running, not where it spent its time.
A hot loop that never blocks is barely visible in it. The profile's `source`
field says which one you are reading, `on-cpu` or `sched-switch`, and
`podtrace_agent_oncpu_sampler_cpus` is 0 on a node that fell back.

### Reading it

```bash
kubectl podtrace status --profile shop/checkout
```

```
PROFILE shop/checkout · on-cpu · 18432 samples on 2 node(s)
  22.8%  encoding/json.(*decodeState).object
  16.2%  runtime.mallocgc
   ...

SLOWEST 1% OF REQUESTS · ≥180ms–240ms · 14 of 1400 requests caught on CPU · 612 samples
  41.0%  main.(*Checkout).applyDiscounts
  12.3%  encoding/json.(*decodeState).object
```

`status` reads `/profile` from every agent through the API server's pod proxy,
merges the nodes that run the workload, and prints the hottest functions with
their share of the samples. A frame's share is its *self* time: the samples
taken while that function itself was running, not every sample it appears
under. Add `-o json` for the merged profile as JSON, and `--top` to show more
frames.

### Flame graphs

For the whole stacks, ask for folded stacks or a pprof profile:

```bash
# Folded stacks, for flamegraph.pl, speedscope or Grafana's flame graph panel
kubectl podtrace status --profile shop/checkout -o folded > checkout.folded
flamegraph.pl checkout.folded > checkout.svg

# pprof, for go tool pprof and anything that reads it
kubectl podtrace status --profile shop/checkout -o pprof > checkout.pb.gz
go tool pprof -http=: checkout.pb.gz

# Only the stacks of the slowest 1% of requests
kubectl podtrace status --profile shop/checkout --slow-requests -o folded > slow.folded
```

Each node's stacks are merged into one graph. A folded line starts with the
workload as its outermost frame, `shop/checkout;main.main;...;main.price 42`,
so folded files from different workloads can be concatenated into one graph. A
pprof profile carries the workload as a sample label, and for on-CPU samples a
`cpu` value of 1/99 s per sample. The command cannot merge a pprof profile
from an `on-cpu` node with one from a `sched-switch` node, because they measure
different things. Use `-o folded` in that case.

### Where the slowest requests spent their CPU

The HTTP/1.x hooks already give every request and its response the same
`correlation_id`: the request's start time in the kernel. When a server reads
a request, over plain TCP or through OpenSSL, GnuTLS or rustls, the hook
records that the reading thread is now serving that request. Every on-CPU sample on that thread
carries the request's correlation id until the response is written. The reply
records how long the request took under the same id. The agent joins the two,
finds each workload's 99th-percentile latency over the window, and profiles
only the samples charged to requests at or above it.

That is the `SLOWEST 1% OF REQUESTS` section, `slowRequests` in the JSON, and
`--slow-requests` for a flame graph. It answers "the p99 requests were slow
because they spent their CPU *here*". When they were slow because they waited
on a lock, a downstream call or the disk, they have no samples. The section
then says how many were caught on a CPU, and "0 of N" means they were waiting,
not computing.

How exact the join is depends on how the runtime maps requests to threads:

| Runtime | Attribution |
|---|---|
| One thread per request (Java servlet containers, Python and Ruby workers, PHP-FPM, most C++ servers) | Exact |
| Go | Approximate. A handler's goroutine can move to another thread; samples after the move are not charged to the request |
| One event loop serving many requests (Node.js, nginx, Envoy) | Not meaningful. A sample is charged to whichever request that thread read last |

A thread entry is trusted only while its request is still open. Once the
response is written, from whatever thread, the next sample on the old thread
drops the entry instead of charging unrelated work to a finished request.

Only HTTP/1.x server-side requests are attributed today, and not those a Go
server reads through `crypto/tls`, whose read path is not hooked for HTTP/1.x.
HTTP/2 and gRPC requests are profiled like any other CPU, but are not joined to
a request.

Each node finds its own threshold, so the merged view shows a range when the
nodes disagree. Samples charged to a request whose reply was never seen, for
example because the connection closed, are given up after a minute. They are
counted in `unjoinedRequestSamples` and still count towards the workload's
profile.

### The agent's /profile endpoint

`status` is the way to read it. The raw per-node endpoint is on the agent's
metrics port:

| Query | Returns |
|---|---|
| `/profile` | JSON: every workload's hot functions and slow-request profile |
| `/profile?format=folded` | Folded stacks, text |
| `/profile?format=pprof` | A gzipped pprof profile |
| `&namespace=shop&workload=checkout` | Only that workload, in any format |
| `&requests=slow` | Only the slowest requests' stacks (folded or pprof) |

```json
{
  "source": "on-cpu",
  "profiles": [
    {
      "namespace": "shop",
      "workload": "checkout",
      "source": "on-cpu",
      "samples": 18432,
      "frames": [
        {"Frame": "encoding/json.(*decodeState).object", "Count": 4211},
        {"Frame": "runtime.mallocgc", "Count": 2980}
      ],
      "schedulerFrames": 0,
      "slowRequests": {
        "quantile": 0.99,
        "thresholdMilliseconds": 180,
        "requests": 1400,
        "sampledRequests": 14,
        "samples": 612,
        "frames": [{"Frame": "main.(*Checkout).applyDiscounts", "Count": 251}]
      }
    }
  ],
  "droppedSamples": 0,
  "unjoinedRequestSamples": 0
}
```

### What keeps it affordable

**Addresses are counted raw and symbolised only when read.** Resolving one
frame means opening the target's executable and reading its symbol table. The
sampler only records addresses; names are looked up when `/profile` is read,
each distinct address once per read, at most 16384 of them. Past that, frames
are shown as hex addresses. For a Go 1.18+ binary the agent keeps only
`.gopclntab`'s function table in memory, 8 bytes per function, and reads each
name from the file when it is asked for. The index is shared by every read, so
a scrape does not parse the binary again.

**Go scheduler frames are skipped on `sched_switch` stacks.** Every
`sched_switch` stack passes through the scheduler on its way off the CPU, so
`runtime.schedule`, `runtime.park_m` and `runtime.mcall` are the innermost
frames of nearly every sample. On those stacks a sample is charged to the first
frame above the scheduler. How many samples that happened to is reported in
`schedulerFrames`. Blocking points such as `runtime.chanrecv`,
`runtime.selectgo` and `sync.runtime_Semacquire` are not skipped, because they
say what the code is waiting on. On-CPU samples skip nothing: a Go scheduler
spinning on a CPU is CPU the workload pays for. The same filter applies to the
diagnose report's hot frames, which prints how many it hid.

**Counts age out.** Samples live in two half-windows that rotate every five
minutes, so a snapshot reflects the last five to ten minutes rather than
everything since the agent started. A workload that was hot an hour ago should
not still look hot.

**It is bounded in both directions.** In the kernel: 8192 distinct stacks and
32768 distinct (process, stack, request) counts between reads. Samples that
cannot be recorded are counted in
`podtrace_agent_oncpu_samples_lost_total{reason}`. In the agent: at most 200
workloads per node, 4096 distinct stacks per workload, and for requests, 8192
latencies (reservoir-sampled past that) and 4096 sampled requests per
workload. Anything refused is counted in `droppedSamples`, so a node profiling
only part of what it sees says so rather than quietly under-reporting.

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
