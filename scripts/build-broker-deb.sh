#!/bin/sh
# Builds opca-acme-broker and its .deb for one Linux platform in a throwaway
# container of that platform (emulated when it isn't the host's), from the
# vendored copy stage-broker-src.sh makes. The binaries land in
# <work>/<arch>/bin and the .deb in <work>/<arch>/deb.
#
# usage: scripts/build-broker-deb.sh [--platform linux/arm64|linux/amd64]
set -eu
usage="usage: $0 [--platform linux/arm64|linux/amd64]"
platform=linux/arm64
case $# in
    0) ;;
    2) [ "$1" = --platform ] || { echo "$usage" >&2; exit 2; }; platform=$2 ;;
    *) echo "$usage" >&2; exit 2 ;;
esac
case $platform in
    linux/arm64 | linux/amd64) arch=${platform#linux/} ;;
    *) echo "$usage" >&2; exit 2 ;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
work=${OPCA_ACME_DOCKER_WORK:-$root/target/acme-docker}
out=$work/$arch

rm -rf "$out/deb" "$out/bin"
mkdir -p "$out/bin"
"$root/scripts/stage-broker-src.sh" "$work"

docker run --rm --platform "$platform" --name "opca-deb-$arch-$$" -v "$work:/work" \
    -w /work/src -e "CARGO_TARGET_DIR=/work/$arch/target" -e "ARCH=$arch" \
    rust:1.99-bookworm sh -ec '
        cargo build --offline --release -p opca-acme-broker
        [ -x "/work/$ARCH/tools/bin/cargo-deb" ] ||
            (cd / && cargo install cargo-deb --version 3.8.0 --locked --root "/work/$ARCH/tools")
        CARGO_NET_OFFLINE=true "/work/$ARCH/tools/bin/cargo-deb" -p opca-acme-broker \
            --no-build --output "/work/$ARCH/deb/"'
cp "$out/target/release/opca-acme-broker" "$out/target/release/opca-acme" "$out/bin/"
