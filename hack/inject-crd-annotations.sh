#!/bin/bash
#
# inject-crd-annotations.sh — post-process CRD YAMLs emitted by
# controller-gen so they participate in the Helm chart's CRD-management
# lifecycle.
#
#   helm.sh/resource-policy: keep   (templated on .Values.crds.keep)
#     Never delete CRDs on `helm uninstall` by default. Losing a CRD
#     orphans every CR of that type — surprising and unsafe. crds.keep
#     was documented in values.yaml but wired to nothing: the annotation
#     was hardcoded, so setting keep=false silently did nothing.
#
# Safe to re-run on already-annotated files: each annotation is a no-op
# if already present.
#
# Usage:
#   hack/inject-crd-annotations.sh <crd-directory>

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

Injects Helm hook + lifecycle annotations into every podtrace.io_*.yaml
CRD in <crd-directory>. Idempotent.
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
		inject_annotations "${file}"
		wrap_in_install_toggle "${file}"
	done

	log_info "processed ${#files[@]} file(s) in ${crd_dir}"
}

wrap_in_install_toggle() {
	local file="$1"
	python3 - "${file}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()

guard_open = "{{- if .Values.crds.install }}"
guard_close = "{{- end }}"

if text.lstrip().startswith(guard_open):
    sys.exit(0)

text = text.lstrip("\n")
if not text.endswith("\n"):
    text += "\n"
path.write_text(f"{guard_open}\n{text}{guard_close}\n")
PY
}

inject_annotations() {
	local file="$1"
	python3 - "${file}" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()

match = re.search(
    r"^(\s+)controller-gen\.kubebuilder\.io/version: \S+",
    text,
    re.MULTILINE,
)
if not match:
    sys.exit(f"inject-crd-annotations: controller-gen marker not found in {path}")

indent = match.group(1)

policy_key = "helm.sh/resource-policy"
if policy_key in text:
    sys.exit(0)

block = "\n".join([
    f"{indent}{{{{- if .Values.crds.keep }}}}",
    f"{indent}{policy_key}: keep",
    f"{indent}{{{{- end }}}}",
])

replacement = match.group(0) + "\n" + block
path.write_text(text.replace(match.group(0), replacement, 1))
PY
}

main "$@"
