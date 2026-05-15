# Metrics and Monitoring

## Overview

Podtrace exposes Prometheus metrics for integration with monitoring systems like Prometheus and Grafana.

## Quick Reference

All metrics are exported per process and per event type.

| Metric | Description |
|---|---|
| `podtrace_rtt_seconds` | Histogram of TCP RTTs |
| `podtrace_rtt_latest_seconds` | Most recent TCP RTT |
| `podtrace_latency_seconds` | Histogram of TCP send/receive latency |
| `podtrace_latency_latest_seconds` | Most recent TCP latency |
| `podtrace_dns_latency_seconds_gauge` | Latest DNS query latency |
| `podtrace_dns_latency_seconds_histogram` | Distribution of DNS query latencies |
| `podtrace_fs_latency_seconds_gauge` | Latest file system operation latency |
| `podtrace_fs_latency_seconds_histogram` | Distribution of file system operation latencies |
| `podtrace_network_bytes_total` | Total bytes transferred over network (TCP/UDP) |
| `podtrace_filesystem_bytes_total` | Total bytes transferred via filesystem ops |
| `podtrace_cpu_block_seconds_gauge` | Latest CPU block time |
| `podtrace_cpu_block_seconds_histogram` | Distribution of CPU block times |
| `podtrace_resource_limit_bytes` | Resource limit in bytes (CPU/Memory/I/O) |
| `podtrace_resource_usage_bytes` | Current resource usage in bytes |
| `podtrace_resource_utilization_percent` | Resource utilization percentage |
| `podtrace_resource_alert_level` | Resource alert level (0=none, 1=warning, 2=critical, 3=emergency) |
| `podtrace_pool_acquires_total` | Total connection pool acquires |
| `podtrace_pool_releases_total` | Total connection pool releases |
| `podtrace_pool_exhausted_total` | Total pool exhaustion events |
| `podtrace_pool_wait_time_seconds` | Histogram of pool wait times |
| `podtrace_pool_connections` | Current number of connections in pool |
| `podtrace_pool_utilization` | Pool utilization percentage |
| `podtrace_redis_latency_seconds` | Distribution of Redis command latencies |
| `podtrace_memcached_latency_seconds` | Distribution of Memcached operation latencies |
| `podtrace_fastcgi_latency_seconds` | Distribution of FastCGI request latencies |
| `podtrace_grpc_latency_seconds` | Distribution of gRPC method call latencies |
| `podtrace_kafka_latency_seconds` | Distribution of Kafka produce/consume latencies |
| `podtrace_kafka_bytes_total` | Total bytes in Kafka produce/consume operations |

## Enabling Metrics

Metrics are enabled when you run Podtrace with the `--metrics` flag. By default, the metrics server starts on `127.0.0.1:3000`.

```bash
./bin/podtrace -n production my-pod --metrics
```

Access metrics at (default address):
```
http://localhost:3000/metrics

To change the bind address and port, set the `PODTRACE_METRICS_ADDR` environment variable before running Podtrace, for example:

```bash
PODTRACE_METRICS_ADDR="0.0.0.0:3000" ./bin/podtrace -n production my-pod --metrics
```
```

## Available Metrics

All metrics are labeled with:
- `type`: Event type (NET, DNS, FS, CPU)
- `process_name`: Name of the process generating the event

### RTT Metrics

**`podtrace_rtt_seconds`** (Histogram)
- Description: Distribution of TCP RTT (Round-Trip Time) measurements
- Buckets: Exponential (0.0001s to ~52s)
- Labels: `type`, `process_name`
- Source: TCP send/receive operations

**`podtrace_rtt_latest_seconds`** (Gauge)
- Description: Most recent TCP RTT measurement
- Labels: `type`, `process_name`
- Updated: On each TCP send/receive event

### Latency Metrics

**`podtrace_latency_seconds`** (Histogram)
- Description: Distribution of TCP connection and operation latencies
- Buckets: Exponential (0.0001s to ~52s)
- Labels: `type`, `process_name`
- Source: TCP connections

**`podtrace_latency_latest_seconds`** (Gauge)
- Description: Most recent TCP latency measurement
- Labels: `type`, `process_name`
- Updated: On each connection event

### DNS Metrics

**`podtrace_dns_latency_seconds_gauge`** (Gauge)
- Description: Latest DNS query latency per process
- Labels: `type`, `process_name`
- Updated: On each DNS lookup

**`podtrace_dns_latency_seconds_histogram`** (Histogram)
- Description: Distribution of DNS query latencies
- Buckets: Exponential (0.0001s to ~52s)
- Labels: `type`, `process_name`
- Source: DNS lookups

### File System Metrics

**`podtrace_fs_latency_seconds_gauge`** (Gauge)
- Description: Latest file system operation latency
- Labels: `type` (write/fsync), `process_name`
- Updated: On each file system operation

**`podtrace_fs_latency_seconds_histogram`** (Histogram)
- Description: Distribution of file system operation latencies
- Buckets: Exponential (0.0001s to ~52s)
- Labels: `type`, `process_name`
- Source: File read/write/fsync operations

### CPU Metrics

**`podtrace_cpu_block_seconds_gauge`** (Gauge)
- Description: Latest CPU block time (thread blocking duration)
- Labels: `type`, `process_name`
- Updated: On each scheduling event

**`podtrace_cpu_block_seconds_histogram`** (Histogram)
- Description: Distribution of CPU block times
- Buckets: Exponential (0.0001s to ~52s)
- Labels: `type`, `process_name`
- Source: CPU scheduling events (sched_switch)

### Connection Pool Metrics

**`podtrace_pool_acquires_total`** (Counter)
- Description: Total number of connection pool acquire attempts
- Labels: `type`, `process_name`

**`podtrace_pool_releases_total`** (Counter)
- Description: Total number of connections returned to the pool
- Labels: `type`, `process_name`

**`podtrace_pool_exhausted_total`** (Counter)
- Description: Total pool exhaustion events (acquire failed — pool full)
- Labels: `type`, `process_name`

**`podtrace_pool_wait_time_seconds`** (Histogram)
- Description: Time spent waiting to acquire a connection from the pool
- Buckets: Exponential (0.0001s to ~52s)
- Labels: `type`, `process_name`

**`podtrace_pool_connections`** (Gauge)
- Description: Current number of active connections in the pool
- Labels: `type`, `process_name`

**`podtrace_pool_utilization`** (Gauge)
- Description: Connection pool utilization as a percentage
- Labels: `type`, `process_name`

### Language-Runtime Adapter Metrics

**`podtrace_redis_latency_seconds`** (Histogram)
- Description: Distribution of Redis command latencies (hiredis uprobes)
- Labels: `type`, `process_name`
- Source: `redisCommand` / `redisCommandArgv` uprobes

**`podtrace_memcached_latency_seconds`** (Histogram)
- Description: Distribution of Memcached operation latencies (libmemcached uprobes)
- Labels: `type`, `process_name`
- Source: `memcached_get`, `memcached_set`, `memcached_delete` uprobes

**`podtrace_fastcgi_latency_seconds`** (Histogram)
- Description: Distribution of FastCGI request latencies (unix-socket kprobes, BTF-only)
- Labels: `type`, `process_name`
- Source: FastCGI request/response kprobes

**`podtrace_grpc_latency_seconds`** (Histogram)
- Description: Distribution of gRPC method call latencies
- Labels: `type`, `process_name`
- Source: `tcp_sendmsg` kprobe filtered by `PODTRACE_GRPC_PORT` (default 50051)

**`podtrace_kafka_latency_seconds`** (Histogram)
- Description: Distribution of Kafka produce and consume latencies (librdkafka uprobes)
- Labels: `type`, `process_name`, `operation` (produce or fetch)
- Source: `rd_kafka_produce`, `rd_kafka_consumer_poll` uprobes

**`podtrace_kafka_bytes_total`** (Counter)
- Description: Total bytes in Kafka produce/consume operations
- Labels: `type`, `process_name`, `operation` (produce or fetch)
- Use with `rate()` to get bytes/second throughput

## Prometheus Configuration

Add a scrape job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'podtrace'
    static_configs:
      - targets: ['<PODTRACE_HOST>:3000']
        labels:
          instance: 'podtrace'
```

Replace `<PODTRACE_HOST>` with:
- `localhost` if running locally
- Pod IP if running in Kubernetes
- Host IP if running on a node

### Kubernetes Service Discovery

For dynamic discovery in Kubernetes:

```yaml
scrape_configs:
  - job_name: 'podtrace'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        regex: podtrace
        action: keep
      - source_labels: [__meta_kubernetes_pod_ip]
        target_label: __address__
        replacement: '${1}:3000'
```

## Grafana Dashboard

A pre-built Grafana dashboard is included at:
```
internal/metricsexporter/dashboard/PodTrace-Dashboard.json
```

### Importing the Dashboard

1. Open Grafana
2. Go to **Dashboards** → **New** → **Import**
3. Upload `PodTrace-Dashboard.json` or paste its contents
4. Select your Prometheus datasource
5. Click **Import**

### Dashboard Panels

The dashboard includes:

- **RTT Distribution**: Histogram of TCP RTTs
- **Latest RTT**: Current RTT values
- **Connection Latency**: TCP connection latencies
- **DNS Latency**: DNS lookup latencies
- **File System Latency**: FS operation latencies
- **I/O Bandwidth**: Network and filesystem throughput metrics
- **CPU Block Time**: Thread blocking durations
- **Per-Process Metrics**: Breakdown by process name

## Query Examples

### Average RTT by Process

```promql
rate(podtrace_rtt_seconds_sum[5m]) / rate(podtrace_rtt_seconds_count[5m])
```

### P95 DNS Latency

```promql
histogram_quantile(0.95, 
  rate(podtrace_dns_latency_seconds_histogram_bucket[5m])
)
```

### Top Processes by Event Count

```promql
topk(10, 
  sum(rate(podtrace_rtt_seconds_count[5m])) by (process_name)
)
```

### File System Operation Rate

```promql
sum(rate(podtrace_fs_latency_seconds_count[5m])) by (type, process_name)
```

### CPU Block Time P99

```promql
histogram_quantile(0.99,
  rate(podtrace_cpu_block_seconds_histogram_bucket[5m])
)
```

### I/O Bandwidth Metrics

**`podtrace_network_bytes_total`** (Counter)
- Description: Total bytes transferred over network (TCP/UDP send/receive)
- Labels: `type`, `process_name`, `direction` (send or recv)
- Use with `rate()` to get bytes/second

**`podtrace_filesystem_bytes_total`** (Counter)
- Description: Total bytes transferred via filesystem operations (read/write)
- Labels: `type`, `process_name`, `operation` (read or write)
- Use with `rate()` to get bytes/second

### I/O Bandwidth Query Examples

#### Network Throughput (bytes/second)

```promql
# Total network throughput
sum(rate(podtrace_network_bytes_total[5m])) by (direction)

# Network throughput by process
sum(rate(podtrace_network_bytes_total[5m])) by (process_name, direction)

# TCP send throughput
sum(rate(podtrace_network_bytes_total{direction="send"}[5m])) by (process_name)
```

#### Filesystem Throughput (bytes/second)

```promql
# Total filesystem throughput
sum(rate(podtrace_filesystem_bytes_total[5m])) by (operation)

# Filesystem throughput by process
sum(rate(podtrace_filesystem_bytes_total[5m])) by (process_name, operation)

# Write throughput
sum(rate(podtrace_filesystem_bytes_total{operation="write"}[5m])) by (process_name)
```

## Security

The metrics endpoint includes:

- **Security Headers**:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`

- **Rate Limiting**: 10 requests per second with burst of 20

- **Localhost Binding**: Only accessible from localhost by default

## Performance

- **Low Overhead**: Metrics collection adds minimal overhead
- **Efficient**: Uses Prometheus client library with efficient data structures
- **Non-Blocking**: Metrics collection doesn't block event processing

## Troubleshooting

**Metrics not appearing:**
- Verify metrics server is running: `curl http://localhost:3000/metrics`
- Check Prometheus can reach the endpoint
- Verify network connectivity

**High cardinality:**
- Process names can create high cardinality
- Consider filtering or aggregating by process name
- Use recording rules for expensive queries

**Rate limiting:**
- If you see "Rate limit exceeded", reduce scrape frequency
- Default: 10 req/s with burst of 20

## Resource Limit Metrics

**`podtrace_resource_limit_bytes`** (Gauge)
- Description: Resource limit in bytes (or CPU quota in microseconds)
- Labels: `resource_type` (cpu, memory, io), `namespace`
- Updated: When resource limits are read from cgroup files

**`podtrace_resource_usage_bytes`** (Gauge)
- Description: Current resource usage in bytes (or CPU time in microseconds)
- Labels: `resource_type` (cpu, memory, io), `namespace`
- Updated: Periodically (every 5 seconds by default)

**`podtrace_resource_utilization_percent`** (Gauge)
- Description: Resource utilization percentage (usage/limit * 100)
- Labels: `resource_type` (cpu, memory, io), `namespace`
- Range: 0-100 (values >100 indicate limit exceeded)
- Updated: Periodically (every 5 seconds by default)

**`podtrace_resource_alert_level`** (Gauge)
- Description: Resource alert level: 0=none, 1=warning (80%), 2=critical (90%), 3=emergency (95%)
- Labels: `resource_type` (cpu, memory, io), `namespace`
- Updated: When utilization crosses thresholds

### Resource Limit Query Examples

#### Current CPU Utilization
```promql
podtrace_resource_utilization_percent{resource_type="cpu"}
```

#### Memory Usage vs Limit
```promql
# Current memory usage
podtrace_resource_usage_bytes{resource_type="memory"}

# Memory limit
podtrace_resource_limit_bytes{resource_type="memory"}

# Memory utilization percentage
podtrace_resource_utilization_percent{resource_type="memory"}
```

#### Alert on High Resource Usage
```promql
# Warning level (80%+)
podtrace_resource_alert_level >= 1

# Critical level (90%+)
podtrace_resource_alert_level >= 2

# Emergency level (95%+)
podtrace_resource_alert_level >= 3
```

#### Resource Usage by Namespace
```promql
# CPU utilization by namespace
sum(podtrace_resource_utilization_percent{resource_type="cpu"}) by (namespace)

# Memory usage by namespace
sum(podtrace_resource_usage_bytes{resource_type="memory"}) by (namespace)
```

#### Resource Limit Exceeded
```promql
# Resources exceeding their limits
podtrace_resource_utilization_percent > 100
```