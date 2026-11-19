#!/usr/bin/env bash
#
# package-release-tarball.sh — packs one CLI release tarball reproducibly.
#
# The same files must give the same bytes, so a re-run of the release job
# uploads tarballs whose sha256 still matches what krew and checksums.txt
# already published. Every entry gets the commit's timestamp, root:0
# ownership and a fixed mode, the files keep the order they are given in
# (directory contents are sorted by name), and gzip leaves its own timestamp
# and the file name out of the header.
#
# Usage:
#   SOURCE_DATE_EPOCH=<unix seconds> package-release-tarball.sh \
#     <staging-dir> <output.tar.gz> <file>...
set -euo pipefail

if [[ $# -lt 3 ]]; then
	echo "usage: SOURCE_DATE_EPOCH=<unix seconds> $0" \
		"<staging-dir> <output.tar.gz> <file>..." >&2
	exit 2
fi
if [[ ! "${SOURCE_DATE_EPOCH:-}" =~ ^[0-9]+$ ]]; then
	echo "$0: SOURCE_DATE_EPOCH must be a unix timestamp," \
		"got '${SOURCE_DATE_EPOCH:-}'" >&2
	exit 2
fi

staging="$1"
out="$2"
shift 2

tar --sort=name \
	--owner=0 --group=0 --numeric-owner \
	--mtime="@${SOURCE_DATE_EPOCH}" \
	--mode='u+rwX,go+rX,go-w' \
	--format=gnu \
	-C "${staging}" -cf - "$@" | gzip -n -9 >"${out}"
