.PHONY: all build clean test check-go test-unit test-integration test-bench coverage \
        generate manifests clientset envtest docker-build helm-lint helm-template operator-tools \
        chainsaw chainsaw-tools \
        e2e-kind e2e-kind-cleanup \
        bundle bundle-validate bundle-build bundle-push bundle-clean

CLANG ?= clang
LLC ?= llc
# Prefer /usr/local/go/bin/go if available (newer Go versions), otherwise use system go
GO ?= $(shell if [ -f /usr/local/go/bin/go ]; then echo /usr/local/go/bin/go; else echo go; fi)
BPF_SRC = bpf/podtrace.bpf.c bpf/network.c bpf/filesystem.c bpf/cpu.c bpf/memory.c
BPF_OBJ = internal/ebpf/embedded/podtrace.$(BPF_GOARCH).bpf.o
BPF_GEN_DIR = bpf/.generated
VMLINUX_GEN = $(BPF_GEN_DIR)/vmlinux.h
BINARY = bin/podtrace

# Export GOTOOLCHAIN=auto to automatically download required Go version (Go 1.21+)
# For Go < 1.21, user needs to upgrade Go manually
export GOTOOLCHAIN=auto

BPF_MCPU ?= v2
BPF_GOARCH ?= $(shell $(GO) env GOARCH)

ifeq ($(BPF_GOARCH),amd64)
  BPF_ARCH_DEFINE = -D__TARGET_ARCH_x86
else ifeq ($(BPF_GOARCH),arm64)
  BPF_ARCH_DEFINE = -D__TARGET_ARCH_arm64
else ifeq ($(BPF_GOARCH),ppc64le)
  BPF_ARCH_DEFINE = -D__TARGET_ARCH_powerpc
else ifeq ($(BPF_GOARCH),s390x)
  BPF_ARCH_DEFINE = -D__TARGET_ARCH_s390
else ifeq ($(BPF_GOARCH),riscv64)
  BPF_ARCH_DEFINE = -D__TARGET_ARCH_riscv
else
  BPF_ARCH_DEFINE = -D__TARGET_ARCH_x86
endif

LIBBPF_INCLUDE ?= /usr/include
BPF_CFLAGS = -O2 -g -target bpf $(BPF_ARCH_DEFINE) -mcpu=$(BPF_MCPU) \
	-Wno-missing-declarations \
	-I$(LIBBPF_INCLUDE) -I$(BPF_GEN_DIR)

all: check-go build

check-go:
	@if ! $(GO) version | grep -qE "go1\.(2[1-9]|[3-9][0-9])"; then \
		echo ""; \
		echo "   Error: Go 1.24+ required (or Go 1.21+ with GOTOOLCHAIN=auto)"; \
		echo "   Current version: $$($(GO) version)"; \
		echo "   Using: $(GO)"; \
		echo ""; \
		echo "   Quick upgrade (recommended):"; \
		echo "   wget -q https://go.dev/dl/go1.24.0.linux-amd64.tar.gz && \\"; \
		echo "   sudo rm -rf /usr/local/go && \\"; \
		echo "   sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz && \\"; \
		echo "   export PATH=\$$PATH:/usr/local/go/bin && \\"; \
		echo "   /usr/local/go/bin/go version"; \
		echo ""; \
		echo "   Or visit: https://go.dev/dl/"; \
		echo ""; \
		exit 1; \
	fi

# Regenerate vmlinux.h from the running kernel's BTF when bpftool is available.
# This gives CO-RE-correct type definitions and avoids register-name mismatches
# between the kernel BTF (short names: ax/si/di) and user-space ptrace.h headers.
# When vmlinux.h is generated from BTF, pass -DPODTRACE_VMLINUX_FROM_BTF so that
# common.h skips its placeholder struct definitions (pt_regs, sockaddr_in).
VMLINUX_BTF  = /sys/kernel/btf/vmlinux
HAVE_BPFTOOL := $(shell command -v bpftool 2>/dev/null)
HAVE_WORKING_BPFTOOL := $(shell bpftool version >/dev/null 2>&1 && echo yes)
HAVE_BTF     := $(shell test -r $(VMLINUX_BTF) && echo yes)

ifneq ($(HAVE_BPFTOOL),)
  ifeq ($(HAVE_WORKING_BPFTOOL),yes)
    ifeq ($(HAVE_BTF),yes)
      USE_BTF_VMLINUX := yes
      BPF_CFLAGS += -DPODTRACE_VMLINUX_FROM_BTF
    endif
  endif
endif

ifeq ($(HAVE_BTF),yes)
  ifneq ($(HAVE_BPFTOOL),)
    ifneq ($(HAVE_WORKING_BPFTOOL),yes)
      $(warning bpftool found but unusable; falling back to stub bpf/vmlinux.h)
    endif
  endif
endif

ifdef USE_BTF_VMLINUX
# /sys/kernel/btf/vmlinux is a sysfs pseudo-file whose modification time can be
# unreliable for make dependency checks. Use a phony intermediate so generated
# vmlinux.h is always refreshed when bpftool is available.
.PHONY: _vmlinux_btf_gen
_vmlinux_btf_gen:
	@mkdir -p "$(BPF_GEN_DIR)"
	@echo "Regenerating $(VMLINUX_GEN) from kernel BTF..."
	bpftool btf dump file $(VMLINUX_BTF) format c > "$(VMLINUX_GEN)"

$(VMLINUX_GEN): _vmlinux_btf_gen
else
$(VMLINUX_GEN):
	@mkdir -p "$(BPF_GEN_DIR)"
	@[ -f bpf/vmlinux.h ] || (echo "Error: bpf/vmlinux.h missing and bpftool unavailable"; exit 1)
	@cp bpf/vmlinux.h "$(VMLINUX_GEN)"
endif

$(BPF_OBJ): $(VMLINUX_GEN) bpf/podtrace.bpf.c bpf/*.h bpf/network.c bpf/filesystem.c bpf/cpu.c bpf/memory.c
	@mkdir -p $(dir $(BPF_OBJ))
	$(CLANG) $(BPF_CFLAGS) -Ibpf -I. -c bpf/podtrace.bpf.c -o $(BPF_OBJ)

build: $(BPF_OBJ)
	@mkdir -p bin
	$(GO) build -tags embed_bpf \
	  -ldflags "-X $(MODULE)/internal/config.Version=$(VERSION) \
	            -X $(MODULE)/internal/config.Commit=$(COMMIT)" \
	  -o $(BINARY) ./cmd/podtrace

# Release: produce cross-arch tarballs for linux+darwin × amd64+arm64.
# Each binary embeds the per-arch BPF object via the embed_bpf tag.
RELEASE_DIR ?= release
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
MODULE = github.com/podtrace/podtrace
RELEASE_TARGETS = linux-amd64 linux-arm64 darwin-amd64 darwin-arm64

.PHONY: release release-bpf-objects

release-bpf-objects:
	$(MAKE) internal/ebpf/embedded/podtrace.amd64.bpf.o BPF_GOARCH=amd64
	$(MAKE) internal/ebpf/embedded/podtrace.arm64.bpf.o BPF_GOARCH=arm64

release: release-bpf-objects
	@rm -rf $(RELEASE_DIR)
	@mkdir -p $(RELEASE_DIR)
	@set -e; \
	for tgt in $(RELEASE_TARGETS); do \
	  os=$${tgt%%-*}; arch=$${tgt##*-}; \
	  echo ">>> Building podtrace for $$os/$$arch (VERSION=$(VERSION))"; \
	  staging="$(RELEASE_DIR)/staging-$$os-$$arch"; \
	  mkdir -p "$$staging"; \
	  GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
	    $(GO) build -trimpath -tags=embed_bpf \
	      -ldflags "-s -w \
	        -X $(MODULE)/internal/config.Version=$(VERSION) \
	        -X $(MODULE)/internal/config.Commit=$(COMMIT)" \
	      -o "$$staging/podtrace" ./cmd/podtrace; \
	  if [ ! -s "$$staging/podtrace" ]; then \
	    echo "::error::go build produced empty/missing binary for $$os/$$arch"; \
	    exit 1; \
	  fi; \
	  cp LICENSE README.md CHANGELOG.md "$$staging/"; \
	  ( cd "$(RELEASE_DIR)" && \
	    tar --sort=name --owner=root:0 --group=root:0 \
	        -czf "podtrace_$$os""_""$$arch.tar.gz" \
	        -C "staging-$$os-$$arch" \
	        podtrace LICENSE README.md CHANGELOG.md ); \
	  rm -rf "$$staging"; \
	done
	cd $(RELEASE_DIR) && sha256sum podtrace_*.tar.gz > checksums.txt
	@echo ""
	@echo "=== Tarballs ==="
	@ls -lh $(RELEASE_DIR)/podtrace_*.tar.gz
	@echo ""
	@echo "=== checksums.txt ==="
	@cat $(RELEASE_DIR)/checksums.txt

clean:
	rm -f internal/ebpf/embedded/podtrace.*.bpf.o
	rm -f $(BINARY)
	rm -rf bin
	rm -rf $(RELEASE_DIR)
	rm -f coverage.out coverage.html
	rm -rf "$(BPF_GEN_DIR)"

deps:
	$(GO) mod download
	$(GO) mod tidy

test: test-fast

test-fast:
	@echo "Running fast unit tests (no race detection)..."
	$(GO) test -short -count=1 -parallel=4 -coverprofile=coverage.out -covermode=atomic $(shell $(GO) list ./... | grep -v '/test$$')

test-unit:
	@echo "Running unit tests with race detection..."
	$(GO) test -short -count=1 -race -coverprofile=coverage.out -covermode=atomic $(shell $(GO) list ./... | grep -v '/test$$')

test-unit-verbose:
	@echo "Running unit tests with verbose output..."
	$(GO) test -v -short -count=1 -race -coverprofile=coverage.out -covermode=atomic $(shell $(GO) list ./... | grep -v '/test$$')

test-integration:
	@echo "Running integration tests..."
	$(GO) test -v -tags=integration ./test

test-bench:
	@echo "Running benchmarks..."
	$(GO) test -bench=. -benchmem ./...

test-all: test-unit test-bench
	@if [ -n "$$CI" ]; then \
		$(GO) test -tags=integration ./test; \
	fi

test-changed:
	@echo "Running tests for changed packages only..."
	@if command -v git >/dev/null 2>&1; then \
		CHANGED=$$(git diff --name-only HEAD | grep '\.go$$' | xargs -r dirname | sort -u | sed 's|^|./|' | grep -E '^(./cmd|./internal)' || echo ""); \
		if [ -n "$$CHANGED" ]; then \
			echo "Testing changed packages: $$CHANGED"; \
			$(GO) test -short -count=1 -parallel=4 $$CHANGED; \
		else \
			echo "No changed Go files found"; \
		fi \
	else \
		echo "git not found, running all tests"; \
		$(GO) test -short -count=1 -parallel=4 $(shell $(GO) list ./... | grep -v '/test$$'); \
	fi

coverage: test-unit
	@echo "Generating coverage report..."
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@echo "Coverage summary:"
	$(GO) tool cover -func=coverage.out | tail -1

# ------------------------------------------------------------------------------
# Operator (Phase 0/1+) — CRD code generation, manifest generation, container
# image. These targets are independent of the eBPF build; they operate on the
# Go type definitions under ./api/v1alpha1 and on ./deploy/charts.
# ------------------------------------------------------------------------------

CONTROLLER_GEN_VERSION ?= v0.16.5
CONTROLLER_GEN ?= $(shell go env GOPATH 2>/dev/null)/bin/controller-gen
CRD_OUT_DIR ?= deploy/charts/podtrace/templates/crds
BOILERPLATE ?= hack/boilerplate.go.txt

IMAGE_REPO ?= ghcr.io/gma1k/podtrace
IMAGE_TAG  ?= dev
IMAGE      ?= $(IMAGE_REPO):$(IMAGE_TAG)

# operator-tools installs controller-gen at a pinned version. Safe to run on
# every invocation; the `go install` is a no-op if already present.
operator-tools:
	@GOBIN=$(dir $(CONTROLLER_GEN)) $(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

# generate (re)emits api/v1alpha1/zz_generated.deepcopy.go from the type
# definitions. Run after any api/ type change.
generate: operator-tools
	$(CONTROLLER_GEN) object:headerFile=$(BOILERPLATE) paths=./api/v1alpha1/...

# clientset regenerates the typed Kubernetes clientset under pkg/client/.
# Controller-runtime operators do not need this (client.Client covers CRUD),
# but external tooling and hook scripts commonly expect a typed clientset.
# The generated files are committed so consumers do not need codegen.
CLIENT_GEN_VERSION ?= v0.34.2
CLIENT_GEN ?= $(shell go env GOPATH 2>/dev/null)/bin/client-gen
clientset:
	@GOBIN=$(dir $(CLIENT_GEN)) $(GO) install k8s.io/code-generator/cmd/client-gen@$(CLIENT_GEN_VERSION)
	$(CLIENT_GEN) \
	  --go-header-file=$(BOILERPLATE) \
	  --clientset-name=versioned \
	  --input-base="" \
	  --input=github.com/podtrace/podtrace/api/v1alpha1 \
	  --output-dir=pkg/client/clientset \
	  --output-pkg=github.com/podtrace/podtrace/pkg/client/clientset

manifests: operator-tools
	$(CONTROLLER_GEN) crd paths=./api/v1alpha1/... output:crd:artifacts:config=$(CRD_OUT_DIR)
	@./hack/inject-crd-annotations.sh $(CRD_OUT_DIR)
	@# Emit the webhook manifest to hack/reference/ as a diff target: the
	@# Helm template at templates/validating-webhook.yaml is hand-authored,
	@# but must stay in sync with the paths/rules kubebuilder generates
	@# from the +kubebuilder:webhook markers. CI compares the two.
	@mkdir -p hack/reference
	$(CONTROLLER_GEN) webhook paths=./api/v1alpha1/... output:webhook:artifacts:config=hack/reference

# docker-build produces the container image used by the CLI, agent, operator,
# and session Jobs. Override IMAGE_REPO / IMAGE_TAG to push to your registry.
docker-build:
	docker build \
	  --build-arg VERSION=$(IMAGE_TAG) \
	  --build-arg COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown) \
	  -t $(IMAGE) .

# envtest runs the CRD schema validation suite against a real
# kube-apiserver + etcd managed by controller-runtime's envtest harness.
# The harness binaries are downloaded on demand by setup-envtest. Gated
# by the `envtest` build tag so `go test ./...` stays CI-friendly when
# the binaries are absent.
ENVTEST_K8S_VERSION ?= 1.30.x
ENVTEST_BIN_DIR ?= $(shell go env GOPATH 2>/dev/null)/envtest-assets
SETUP_ENVTEST ?= $(shell go env GOPATH 2>/dev/null)/bin/setup-envtest
envtest:
	@GOBIN=$(dir $(SETUP_ENVTEST)) $(GO) install sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.19
	KUBEBUILDER_ASSETS=$$($(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir=$(ENVTEST_BIN_DIR) -p path) \
	  $(GO) test -tags=envtest -count=1 -timeout 300s \
	    ./api/v1alpha1/... ./internal/operator/... ./internal/agent/...

helm-lint:
	helm lint deploy/charts/podtrace

# e2e-kind runs the Phase-2 smoke script against whatever kind cluster
# the user's KUBECONFIG currently points at. The script is idempotent;
# re-running it upgrades an existing release in place.
e2e-kind:
	test/e2e/kind-smoke.sh

# e2e-kind-cleanup tears down the e2e release and sample namespace.
e2e-kind-cleanup:
	test/e2e/kind-smoke.sh cleanup

# chainsaw runs the declarative e2e suite under test/chainsaw/. Expects
# a working operator install (run e2e-kind first) and the chainsaw CLI
# on PATH. Each test case creates its own namespace, so they can run
# in parallel against the same cluster.
CHAINSAW ?= $(shell command -v chainsaw 2>/dev/null)
CHAINSAW_VERSION ?= latest
chainsaw-tools:
	@if [ -z "$(CHAINSAW)" ]; then \
	  echo "Installing chainsaw@$(CHAINSAW_VERSION)..."; \
	  $(GO) install github.com/kyverno/chainsaw@$(CHAINSAW_VERSION); \
	fi

chainsaw: chainsaw-tools
	$(or $(CHAINSAW),chainsaw) test --test-dir test/chainsaw/tests

helm-template:
	helm template podtrace deploy/charts/podtrace

build-setup: build
	@echo "Setting capabilities..."
	@sudo ./scripts/setup-capabilities.sh || (echo "Warning: Failed to set capabilities. Run manually: sudo ./scripts/setup-capabilities.sh" && exit 1)

CHART_APP_VERSION := $(shell awk '/^appVersion:/{gsub(/"/,"",$$2); print $$2; exit}' deploy/charts/podtrace/Chart.yaml)
BUNDLE_VERSION ?= $(CHART_APP_VERSION)
PREVIOUS_VERSION ?=
BUNDLE_IMG ?= ghcr.io/gma1k/podtrace-bundle:v$(BUNDLE_VERSION)
BUNDLE_DIR := bundle/$(BUNDLE_VERSION)

bundle:
	VERSION=$(BUNDLE_VERSION) PREVIOUS_VERSION=$(PREVIOUS_VERSION) ./scripts/build-olm-bundle.sh

bundle-validate: bundle
	@command -v operator-sdk >/dev/null 2>&1 || \
	  { echo "operator-sdk not on PATH; install from https://sdk.operatorframework.io/"; exit 1; }
	operator-sdk bundle validate $(BUNDLE_DIR) --select-optional name=community

bundle-build: bundle
	docker build -t $(BUNDLE_IMG) -f $(BUNDLE_DIR)/bundle.Dockerfile $(BUNDLE_DIR)

bundle-push:
	docker push $(BUNDLE_IMG)

bundle-clean:
	rm -rf bundle/

help:
	@echo "Available targets:"
	@echo "  all              - Build everything (default)"
	@echo "  build            - Build the Go binary"
	@echo "  build-setup      - Build and set capabilities (requires sudo)"
	@echo "  clean            - Remove build artifacts"
	@echo "  deps             - Download and tidy Go dependencies"
	@echo "  test             - Run fast unit tests (no race detection, parallel)"
	@echo "  test-fast        - Run fast unit tests (no race detection, parallel)"
	@echo "  test-unit        - Run unit tests with race detection"
	@echo "  test-unit-verbose - Run unit tests with verbose output"
	@echo "  test-changed     - Run tests only for changed packages (requires git)"
	@echo "  test-integration - Run integration tests (requires K8s cluster)"
	@echo "  test-bench       - Run benchmark tests"
	@echo "  test-all         - Run all tests"
	@echo "  coverage         - Generate test coverage report"