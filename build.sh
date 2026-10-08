#!/usr/bin/env bash
# Build the xray binary from this checkout, with the same flags as the
# release workflow (.github/workflows/release.yml).
#
# Usage: ./build.sh [output]        (default output: ./xray)
#
# Cross-compile by setting GOOS / GOARCH (and GOARM, GOMIPS, ... as needed):
#   GOOS=linux GOARCH=arm64 ./build.sh xray-linux-arm64
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

output="${1:-xray}"

if ! command -v go >/dev/null 2>&1; then
	echo "error: Go is not installed; this project needs Go $(awk '/^go /{print $2}' go.mod) or newer" >&2
	exit 1
fi

# The commit is stamped into `xray version`; core.go uses 7 characters.
commit="$(git rev-parse --short=7 HEAD 2>/dev/null || echo Custom)"
if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
	commit="${commit}-dirty"
fi

echo "Building ${output} (commit ${commit}, $(go env GOOS)/$(go env GOARCH))..."
CGO_ENABLED=0 go build \
	-o "${output}" \
	-trimpath -buildvcs=false \
	-gcflags="all=-l=4" \
	-ldflags="-X github.com/xtls/xray-core/core.build=${commit} -s -w -buildid=" \
	./main

if [ "$(go env GOOS)/$(go env GOARCH)" = "$(go env GOHOSTOS)/$(go env GOHOSTARCH)" ]; then
	case "${output}" in
	/*) bin="${output}" ;;
	*) bin="./${output#./}" ;;
	esac
	"${bin}" version | sed -n 1p
fi
echo "Built ${output}"
