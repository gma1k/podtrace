#!/usr/bin/env bash
# Post-create setup for the podtrace dev container.
set -euo pipefail

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
	clang llvm libbpf-dev libelf-dev bpftool \
	make pkg-config bc libcap2-bin

go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2

go mod download

echo "podtrace dev container ready - build with: make"
