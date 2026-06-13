#!/bin/bash
set -e

NAMESPACE="podtrace-test"
POD_NAME="${1:-nginx-cpu-test}"
DURATION="${2:-20s}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
	echo "$@"
}

ensure_pod() {
	local pod="$1"
	local ns="$2"

	if kubectl get pod "${pod}" -n "${ns}" &>/dev/null; then
		return 0
	fi

	log "Pod ${pod} not found in namespace ${ns}; creating test fixtures..."
	if ! kubectl apply -f "${SCRIPT_DIR}/test-pods-full.yaml"; then
		log "Error: failed to apply ${SCRIPT_DIR}/test-pods-full.yaml"
		exit 1
	fi

	if ! kubectl wait --for=condition=Ready "pod/${pod}" -n "${ns}" --timeout=120s; then
		log "Error: Pod ${pod} did not become Ready in namespace ${ns}"
		kubectl get pods -n "${ns}" || log "Namespace ${ns} not found"
		exit 1
	fi
}

check_podtrace_binary() {
	if [[ ! -f "./bin/podtrace" ]]; then
		log "Error: ./bin/podtrace not found. Run 'make build' first."
		exit 1
	fi
}

run_diagnose() {
	local pod="$1"
	local ns="$2"
	local duration="$3"

	log "Running diagnose mode..."
	./bin/podtrace -n "${ns}" "${pod}" --diagnose "${duration}"
}

main() {
	log "=== Testing podtrace on ${POD_NAME} for ${DURATION} ==="
	log ""

	ensure_pod "${POD_NAME}" "${NAMESPACE}"
	check_podtrace_binary
	run_diagnose "${POD_NAME}" "${NAMESPACE}" "${DURATION}"
}

main
