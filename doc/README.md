# Podtrace Documentation

Welcome to the `Podtrace` documentation. This directory contains comprehensive guides for using, understanding, and developing with `Podtrace`.

## Documentation Index

### Core
- **[Architecture](architecture.md)** - System architecture, components, and data flow
- **[Installation](installation.md)** - Installation guide, prerequisites, and troubleshooting
- **[Usage Guide](usage.md)** - Usage examples, command-line options, and tips
- **[eBPF Internals](ebpf-internals.md)** - Deep dive into eBPF programs and tracing mechanisms
- **[Event Schema](event-schema.md)** - Binary wire format for BPF ring buffer events
- **[Development](development.md)** - Development guide, code structure, testing, and contributing

### Observability
- **[Metrics](metrics.md)** - Prometheus metrics, Grafana integration, scrape config, and dashboard import
- **[Distributed Tracing Guide](distributed-tracing.md)** - Complete distributed tracing user guide
- **[Tracing Exporters Setup](tracing-exporters.md)** - Detailed exporter configuration (OTLP, Jaeger, Splunk HEC, DataDog, Zipkin)
- **[Alerting Guide](alerting.md)** - Real-time alerts via webhooks, Slack, and Splunk HEC
- **[Performance Profiling](profiling.md)** - On-demand CPU/memory profiling with eBPF event correlation

### Application Tracing
- **[Language-Runtime Adapters](language-runtime-adapters.md)** - Redis, Memcached, FastCGI, gRPC, Kafka uprobes; PII redaction; USDT auto-detection
- **[Multi-Pod Tracing](multi-pod-tracing.md)** - Multi-pod and cross-namespace tracing with selector patterns

### Platform Guides
- **[EKS](eks.md)** - Running Podtrace on Amazon Elastic Kubernetes Service
- **[AKS](aks.md)** - Running Podtrace on Azure Kubernetes Service
- **[GKE](gke.md)** - Running Podtrace on Google Kubernetes Engine
- **[OpenShift](openshift.md)** - Running Podtrace on OpenShift / OKD
- **[Talos Linux](talos.md)** - Running Podtrace on Talos Linux

## Quick Start

1. **New to Podtrace?** Start with [Installation](installation.md), [Usage Guide](usage.md), and [Multi-Pod Tracing](multi-pod-tracing.md)
2. **Want to understand how it works?** Read [Architecture](architecture.md) and [eBPF Internals](ebpf-internals.md)
3. **Need to integrate metrics?** Check [Metrics](metrics.md)
4. **Setting up distributed tracing?** See [Distributed Tracing Guide](distributed-tracing.md) and [Tracing Exporters Setup](tracing-exporters.md)
5. **Setting up alerting?** See [Alerting Guide](alerting.md)
6. **Tracing Redis, gRPC, Kafka?** See [Language-Runtime Adapters](language-runtime-adapters.md)
7. **Running on a managed Kubernetes?** See the Platform Guides above
8. **Contributing?** See [Development](development.md)