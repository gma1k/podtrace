# Podtrace Documentation

Welcome to the `Podtrace` documentation. This directory contains comprehensive guides for using, understanding, and developing with `Podtrace`.

## Documentation Index

### Core
- **[Architecture](architecture.md)** - System architecture, components, and data flow
- **[Installation](installation.md)** - Installation guide, prerequisites, and troubleshooting
- **[Usage Guide](usage.md)** - CLI usage examples, command-line options, and tips
- **[eBPF Internals](ebpf-internals.md)** - Deep dive into eBPF programs and tracing mechanisms
- **[Event Schema](event-schema.md)** - Binary wire format for BPF ring buffer events
- **[Development](development.md)** - Development guide, code structure, testing, and contributing

### Operator (CRD-driven workflows)
- **[Operator](operator.md)** - Operator + agent architecture, helm install, key invariants
- **[Migration](migration.md)** - CLI binary → CR walkthrough with a translation table
- **[PodTrace CR](crd-podtrace.md)** - Continuous tracing via a Custom Resource
- **[PodTraceSession CR](crd-podtracesession.md)** - Bounded diagnose with a report artifact
- **[TracerConfig CR](crd-tracerconfig.md)** - Cluster-wide infrastructure config
- **[ExporterConfig CR](crd-exporterconfig.md)** - Reusable exporter destinations

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
2. **Want declarative tracing via Kubernetes Custom Resources?** Read [Operator](operator.md), then pick [PodTrace](crd-podtrace.md) (continuous) or [PodTraceSession](crd-podtracesession.md) (bounded diagnose)
3. **Already a CLI user moving to CRs?** See the [Migration guide](migration.md)
4. **Want to understand how it works?** Read [Architecture](architecture.md) and [eBPF Internals](ebpf-internals.md)
5. **Need to integrate metrics?** Check [Metrics](metrics.md)
6. **Setting up distributed tracing?** See [Distributed Tracing Guide](distributed-tracing.md) and [Tracing Exporters Setup](tracing-exporters.md)
7. **Setting up alerting?** See [Alerting Guide](alerting.md)
8. **Tracing Redis, gRPC, Kafka?** See [Language-Runtime Adapters](language-runtime-adapters.md)
9. **Running on a managed Kubernetes?** See the Platform Guides above
10. **Contributing?** See [Development](development.md)