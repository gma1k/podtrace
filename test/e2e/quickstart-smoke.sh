#!/bin/bash
#
# quickstart-smoke.sh — end-to-end regression for the
# release-attached quickstart.yaml.
#
# This script does not create a kind cluster (the user is expected to
# have one already). It renders the same quickstart.yaml that
# release.yml produces (helm template + concatenated sample workload),
# applies it, and asserts that the demo PodTraceSession reaches
# phase=Completed with status.summary populated and the reportRef
# ConfigMap created.
#
# Catches regressions in:
#   - chart-rendered operator manifest (CRDs, RBAC, Deployment)
#   - deploy/quickstart-sample.yaml shape
#   - release.yml's quickstart job assembly
#
# Usage:
#
#   test/e2e/quickstart-smoke.sh           # render + apply + assert
#   test/e2e/quickstart-smoke.sh cleanup   # teardown only

set -euo pipefail

readonly SCRIPT_NAME="${0##*/}"
readonly SYSTEM_NS="podtrace-system"
readonly DEMO_NS="podtrace-demo"
readonly SESSION_NAME="demo-trace"
readonly REPORT_CM="nginx-trace-report"

log_err() {
	printf '%s: %s\n' "${SCRIPT_NAME}" "$*" >&2
}

log_info() {
	printf '%s: %s\n' "${SCRIPT_NAME}" "$*"
}

require_tool() {
	if ! command -v "$1" >/dev/null 2>&1; then
		log_err "required tool not on PATH: $1"
		exit 1
	fi
}

repo_root() {
	cd "$(dirname "${BASH_SOURCE[0]}")/../.." >/dev/null 2>&1 && pwd
}

render_quickstart() {
	local root="$1"
	local out="$2"

	helm template podtrace "${root}/deploy/charts/podtrace" \
		--namespace "${SYSTEM_NS}" \
		--include-crds \
		--set namespace.create=true \
		--set operator.enabled=true \
		>"${out}.operator"

	{
		cat "${out}.operator"
		echo "---"
		cat "${root}/deploy/quickstart-sample.yaml"
	} >"${out}"
	rm -f "${out}.operator"

	local lines
	lines=$(wc -l <"${out}")
	log_info "rendered quickstart at ${out} (${lines} lines)"
}

cleanup() {
	log_info "cleaning up"

	kubectl delete ns "${DEMO_NS}" "${SYSTEM_NS}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	kubectl delete crd \
		exporterconfigs.podtrace.io \
		podtraces.podtrace.io \
		podtracesessions.podtrace.io \
		tracerconfigs.podtrace.io \
		--ignore-not-found --wait=false >/dev/null 2>&1 || true
	kubectl delete clusterrole podtrace-operator podtrace-agent --ignore-not-found >/dev/null 2>&1 || true
	kubectl delete clusterrolebinding podtrace-operator podtrace-agent --ignore-not-found >/dev/null 2>&1 || true

	log_info "cleanup issued (deletions run async; kubectl get may still show items for a few seconds)"
}

wait_for() {
	local description="$1"
	local timeout_seconds="$2"
	local check_cmd="$3"

	log_info "waiting for: ${description}"
	local elapsed=0
	while [[ ${elapsed} -lt ${timeout_seconds} ]]; do
		if eval "${check_cmd}" >/dev/null 2>&1; then
			log_info "  ok: ${description}"
			return 0
		fi
		sleep 2
		elapsed=$((elapsed + 2))
	done
	log_err "timeout after ${timeout_seconds}s: ${description}"
	return 1
}

assert_summary_populated() {
	local summary
	summary=$(kubectl -n "${DEMO_NS}" get podtracesession "${SESSION_NAME}" \
		-o jsonpath='{.status.summary}' 2>/dev/null || true)
	if [[ -z "${summary}" || "${summary}" == "null" ]]; then
		log_err "status.summary is empty on ${SESSION_NAME}"
		return 1
	fi
	log_info "  status.summary: ${summary}"
}

assert_report_configmap() {
	if ! kubectl -n "${DEMO_NS}" get cm "${REPORT_CM}" >/dev/null 2>&1; then
		log_err "expected ConfigMap ${DEMO_NS}/${REPORT_CM}"
		return 1
	fi
	local data_keys
	data_keys=$(kubectl -n "${DEMO_NS}" get cm "${REPORT_CM}" \
		-o jsonpath='{range .data.*}{@}{"\n"}{end}' 2>/dev/null)
	data_keys="${data_keys%%$'\n'*}"
	if [[ -z "${data_keys}" ]]; then
		log_err "ConfigMap ${DEMO_NS}/${REPORT_CM} has no data"
		return 1
	fi
	log_info "  report ConfigMap data present (${#data_keys} chars)"
}

wait_namespace_gone() {
	local ns="$1"
	local timeout="${2:-60}"
	local elapsed=0
	while [[ ${elapsed} -lt ${timeout} ]]; do
		if ! kubectl get ns "${ns}" >/dev/null 2>&1; then
			return 0
		fi
		local phase
		phase=$(kubectl get ns "${ns}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
		if [[ "${phase}" != "Terminating" ]]; then
			return 0
		fi
		sleep 2
		elapsed=$((elapsed + 2))
	done
	log_err "namespace ${ns} stuck in Terminating after ${timeout}s"
	return 1
}

main() {
	require_tool kubectl
	require_tool helm

	local action="${1:-run}"
	if [[ "${action}" == "cleanup" ]]; then
		cleanup
		return 0
	fi

	wait_namespace_gone "${SYSTEM_NS}" 90
	wait_namespace_gone "${DEMO_NS}" 60

	local root
	root="$(repo_root)"
	RENDERED="$(mktemp -t quickstart.XXXXXX.yaml)"
	trap 'rm -f "${RENDERED:-}"' EXIT

	log_info "rendering quickstart.yaml from chart + sample"
	render_quickstart "${root}" "${RENDERED}"

	log_info "applying quickstart"
	kubectl apply -f "${RENDERED}" >/dev/null

	wait_for "operator Deployment Ready" 120 \
		"kubectl -n ${SYSTEM_NS} rollout status deploy/podtrace-operator --timeout=60s"

	wait_for "demo PodTraceSession reaches phase=Completed" 180 \
		"[[ \$(kubectl -n ${DEMO_NS} get podtracesession ${SESSION_NAME} -o jsonpath='{.status.phase}' 2>/dev/null) == 'Completed' ]]"

	assert_summary_populated

	assert_report_configmap

	log_info "quickstart smoke passed — cluster state snapshot follows"
	echo
	kubectl -n "${DEMO_NS}" get podtracesession,exporterconfig,deployment
	echo
	kubectl -n "${SYSTEM_NS}" get deploy,daemonset
	echo
	kubectl get tracerconfig
}

main "$@"
