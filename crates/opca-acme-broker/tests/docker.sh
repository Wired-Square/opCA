#!/bin/sh
# Builds the broker and its .deb for one Linux platform, then runs the Docker
# tests against them in containers of that platform.
#
# usage: tests/docker.sh [--platform linux/arm64|linux/amd64]
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
"$root/scripts/build-broker-deb.sh" "$@"
platform=${2:-linux/arm64}
out=${OPCA_ACME_DOCKER_WORK:-$root/target/acme-docker}/${platform#linux/}

OPCA_ACME_DOCKER_TEST=1 OPCA_ACME_DOCKER_PLATFORM="$platform" \
    OPCA_ACME_DOCKER_BIN="$out/bin" OPCA_ACME_DOCKER_DEB="$out/deb" \
    cargo test -p opca-acme-broker --test broker_docker
