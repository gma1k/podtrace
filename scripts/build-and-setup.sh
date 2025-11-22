#!/bin/bash
# Build podtrace and automatically set capabilities

set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

build_podtrace() {
	echo "Building podtrace..."
	cd "${ROOT_DIR}"

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
		echo "✓ Build and setup complete!"
		echo ""
		echo "You can now run podtrace:"
		echo "  ./bin/podtrace -n <namespace> <pod-name>"
	else
		echo ""
		echo "⚠ Build succeeded but failed to set capabilities."
		echo "  Run manually: sudo ./scripts/setup-capabilities.sh"
		exit 1
	fi
}

main() {
	build_podtrace
	set_capabilities
}

main "$@"
