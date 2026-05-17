#!/usr/bin/env bash

set -euo pipefail

REPO="${REPO:-gma1k/podtrace}"

LABELS=(
	feat fix perf docs test ci build chore refactor style
	security deprecate remove revert breaking ignore-for-release
)

AREA_LABELS=(
	area/bpf area/operator area/agent area/cli area/helm
	area/olm area/docs area/tests area/ci
)

VALID_TYPES_RE='^(feat|fix|perf|docs|test|ci|build|chore|refactor|style|security|deprecate|remove|revert)$'

require_gh() {
	if ! command -v gh >/dev/null 2>&1; then
		echo "Error: gh CLI not found. Install from https://cli.github.com/" >&2
		exit 1
	fi
	if ! gh auth status >/dev/null 2>&1; then
		echo "Error: gh CLI is not authenticated. Run 'gh auth login' first." >&2
		exit 1
	fi
}

create_labels() {
	echo "==> Step A: create labels on ${REPO}"
	local label
	for label in "${LABELS[@]}"; do
		if gh label create "${label}" \
			--repo "${REPO}" \
			--description "Conventional-commit type: ${label}" >/dev/null 2>&1; then
			echo "  created: ${label}"
		else
			echo "  exists:  ${label}"
		fi
	done
	for label in "${AREA_LABELS[@]}"; do
		local area="${label#area/}"
		if gh label create "${label}" \
			--repo "${REPO}" \
			--color "0052cc" \
			--description "Codebase area: ${area}" >/dev/null 2>&1; then
			echo "  created: ${label}"
		else
			echo "  exists:  ${label}"
		fi
	done
}

backfill_labels() {
	echo
	echo "==> Step B: backfill labels on merged PRs"
	local jq_filter='.[] | select(.title | test("^[a-z]+(\\([^)]+\\))?!?:")) |
		[(.number|tostring), (.title | capture("^(?<t>[a-z]+)") | .t)] | @tsv'

	local rows
	rows=$(gh pr list --repo "${REPO}" --state merged --base main --limit 200 \
		--json number,title --jq "${jq_filter}")

	if [[ -z "${rows}" ]]; then
		echo "  no merged PRs matched conventional-commit format"
		return 0
	fi

	local number type
	while IFS=$'\t' read -r number type; do
		if [[ "${type}" =~ ${VALID_TYPES_RE} ]]; then
			echo "  PR #${number}: ${type}"
			gh pr edit "${number}" --repo "${REPO}" --add-label "${type}" >/dev/null
		else
			echo "  PR #${number}: skipping unknown type '${type}'"
		fi
	done <<<"${rows}"
}

main() {
	require_gh
	create_labels
	backfill_labels
	echo
	echo "Done. Verify with: gh pr list --repo ${REPO} --label feat --limit 50"
}

main "$@"
