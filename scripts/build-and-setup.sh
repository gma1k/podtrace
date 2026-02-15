#!/bin/bash
# Build podtrace and automatically set capabilities

set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

check_deps() {
	local missing=()
	command -v clang >/dev/null 2>&1 || missing+=(clang)
	command -v go >/dev/null 2>&1 || missing+=(go)
	if [[ ! -f /usr/include/bpf/bpf_helpers.h ]] && [[ ! -f "${LIBBPF_INCLUDE:-/usr/include}/bpf/bpf_helpers.h" ]]; then
		missing+=(libbpf-dev)
	fi
	if [[ ${#missing[@]} -gt 0 ]]; then
		echo "Error: Missing required build tools or headers: ${missing[*]}"
		echo ""
		echo "On Debian/Ubuntu install with:"
		echo "  sudo apt update"
		echo "  sudo apt install -y clang llvm build-essential libbpf-dev"
		echo "  # Go: use go.mod version or install from https://go.dev/dl/"
		echo ""
		exit 1
	fi
}

build_podtrace() {
	echo "Building podtrace..."
	cd "${ROOT_DIR}"

	check_deps
	make clean
	make build

	if [[ ! -f "./bin/podtrace" ]]; then
		echo "Error: Build failed - bin/podtrace not found"
		exit 1
	fi
}

set_capabilities() {
	echo ""
	echo "Setting capabilities..."
	if sudo ./scripts/setup-capabilities.sh; then
		echo ""
		echo "Build and setup complete!"
		echo ""
		echo "You can now run podtrace:"
		echo "  ./bin/podtrace -n <namespace> <pod-name>"
	else
		echo ""
		echo "Build succeeded but failed to set capabilities."
		echo "Run manually: sudo ./scripts/setup-capabilities.sh"
		exit 1
	fi
}

main() {
	build_podtrace
	set_capabilities
}

main "$@"
