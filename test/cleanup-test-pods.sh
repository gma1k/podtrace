#!/bin/bash
# Cleanup script for podtrace test pods

set -e

NAMESPACE="podtrace-test"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'
# YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_header() {
	echo "=== Cleaning up podtrace test environment ==="
	echo ""
}

check_kubectl() {
	if ! command -v kubectl &>/dev/null; then
		echo -e "${RED}Error: kubectl is not installed${NC}"
		exit 1
	fi
}

delete_resources() {
	echo "Deleting test pods and namespace..."
	kubectl delete -f "${SCRIPT_DIR}/test-pods.yaml" --ignore-not-found=true
}

wait_for_namespace_deletion() {
	echo ""
	echo "Waiting for namespace to be deleted..."
	kubectl wait --for=delete namespace/"${NAMESPACE}" --timeout=60s 2>/dev/null || true
}

print_success() {
	echo ""
	echo -e "${GREEN}✓ Cleanup completed${NC}"
}

main() {
	print_header
	check_kubectl
	delete_resources
	wait_for_namespace_deletion
	print_success
}

main "$@"
