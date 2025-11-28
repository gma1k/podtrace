# podtrace Test Environment

This directory contains test pods and scripts to test the podtrace CLI.

## Quick Start

### 1. Setup Test Pods

```bash
cd /path/to/podtrace/test
./setup-test-pods.sh
```

This will:
- Create a `podtrace-test` namespace
- Deploy 3 test pods:
  - `nginx-test`
  - `busybox-test`
  - `alpine-test`

### 2. Test podtrace

```bash
sudo ./bin/podtrace -n podtrace-test nginx-test
```

### 3. Cleanup

```bash
./cleanup-test-pods.sh
```

## Automated Test Runner

Run all tests automatically:

```bash
./test/run-tests.sh
```

## Files

- `test-pods.yaml` - Kubernetes manifests for test pods
- `setup-test-pods.sh` - Script to create test environment
- `cleanup-test-pods.sh` - Script to clean up test environment
- `run-tests.sh` - Automated test runner
- `quick-test.sh` - Quick test script
- `test-debug.sh` - Debug test script
- `test-cpu-usage.sh` - CPU usage test script
