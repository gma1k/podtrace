#!/bin/bash

# Usage:
#   hack/inject-keep-annotation.sh <crd-directory>

set -euo pipefail

readonly SCRIPT_NAME="${0##*/}"

log_err() {
	printf '%s: %s\n' "${SCRIPT_NAME}" "$*" >&2
}

log_info() {
	printf '%s: %s\n' "${SCRIPT_NAME}" "$*"
}

usage() {
	cat >&2 <<USAGE
Usage: ${SCRIPT_NAME} <crd-directory>

Injects helm.sh/resource-policy: keep into every podtrace.io_*.yaml
CRD in <crd-directory>. Safe to re-run on already-annotated files.
USAGE
}

main() {
	if [[ $# -ne 1 ]]; then
		usage
		exit 2
	fi

	local crd_dir="$1"
	if [[ ! -d "${crd_dir}" ]]; then
		log_err "not a directory: ${crd_dir}"
		exit 1
	fi

	shopt -s nullglob
	local files=("${crd_dir}"/podtrace.io_*.yaml)
	if [[ ${#files[@]} -eq 0 ]]; then
		log_err "no CRD files found under ${crd_dir}"
		exit 1
	fi

	local file
	for file in "${files[@]}"; do
		inject_keep_annotation "${file}"
	done

	log_info "processed ${#files[@]} file(s) in ${crd_dir}"
}

inject_keep_annotation() {
	local file="$1"
	python3 - "${file}" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
if "helm.sh/resource-policy" in text:
    sys.exit(0)

match = re.search(
    r"^(\s+)controller-gen\.kubebuilder\.io/version: \S+",
    text,
    re.MULTILINE,
)
if not match:
    sys.exit(f"inject-keep-annotation: controller-gen marker not found in {path}")

indent = match.group(1)
replacement = (
    f"{match.group(0)}\n"
    f"{indent}helm.sh/resource-policy: keep"
)
path.write_text(text.replace(match.group(0), replacement, 1))
PY
}

main "$@"