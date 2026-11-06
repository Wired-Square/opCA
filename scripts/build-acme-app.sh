#!/bin/sh
# Builds the opca-acme ApplianceOS app image for one platform as a docker-load
# tarball, then packs it with a signed index into an archive the console's
# Apps › Install takes. Signs with the throwaway keys in <keys>, made there by
# ApplianceOS's make-app-archive.sh when it holds none; never real keys.
# Without --keys it signs with OPCA_TEST_SIGNING_CERT and OPCA_TEST_SIGNING_KEY
# from .env (base64 of leaf.pem and leaf.key), so a box's source keeps
# verifying across builds.
#
# usage: scripts/build-acme-app.sh [--keys <dir>] [--platform linux/arm64|linux/amd64] [--source <name>]
#
# APPLIANCEOS names an ApplianceOS checkout (default: ../ApplianceOS beside
# this repository). An arm64 build needs wslib-appliance-xtask for its
# erratum check. Output lands in target/acme-app.
set -eu
usage="usage: $0 [--keys <dir>] [--platform linux/arm64|linux/amd64] [--source <name>]"
platform=linux/arm64
source=opca-test
keys=
while [ $# -ge 2 ]; do
    case $1 in
        --keys) keys=$2 ;;
        --platform) platform=$2 ;;
        --source) source=$2 ;;
        *) echo "$usage" >&2; exit 2 ;;
    esac
    shift 2
done
[ $# = 0 ] || { echo "$usage" >&2; exit 2; }
case $platform in
    linux/arm64 | linux/amd64) arch=${platform#linux/} ;;
    *) echo "$usage" >&2; exit 2 ;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "$keys" ]; then
    # .env may be a 1Password-mounted FIFO: test with -e, and read it once.
    if [ -e "$root/.env" ]; then
        while IFS='=' read -r key value; do
            case $key in
                OPCA_TEST_SIGNING_CERT | OPCA_TEST_SIGNING_KEY) export "$key=$value" ;;
            esac
        done <"$root/.env"
    fi
    : "${OPCA_TEST_SIGNING_CERT:?no --keys, and not set in .env}"
    : "${OPCA_TEST_SIGNING_KEY:?no --keys, and not set in .env}"
    keys=$(mktemp -d)
    trap 'rm -rf "$keys"' EXIT
    printf %s "$OPCA_TEST_SIGNING_CERT" | base64 -d >"$keys/leaf.pem"
    printf %s "$OPCA_TEST_SIGNING_KEY" | base64 -d >"$keys/leaf.key"
fi
archiver=${APPLIANCEOS:-$root/../ApplianceOS}/scripts/make-app-archive.sh
[ -x "$archiver" ] || { echo "no $archiver; set APPLIANCEOS" >&2; exit 1; }
out=$root/target/acme-app
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -1)
image=$out/opca-acme-$version-$arch.tar
archive=$out/opca-acme-$version-$arch-$source.tar

label=$(cargo run -q -p opca-acme-broker --example appliance-label -- "$arch")
"$root/scripts/stage-broker-src.sh" "$out"

builder=appliance-image
docker buildx inspect "$builder" >/dev/null 2>&1 ||
    docker buildx create --name "$builder" --driver docker-container >/dev/null
build() {
    docker buildx build --builder "$builder" --platform "$platform" \
        --file "$root/crates/opca-acme-broker/appliance/Dockerfile" "$@" "$out/src"
}
if [ "$arch" = arm64 ]; then
    build --target binary --output "type=local,dest=$out/$arch"
    wslib-appliance-xtask erratum-843419 "$out/$arch/opca-acme-broker"
fi
build \
    --tag "ghcr.io/wired-square/opca-acme:$version" \
    --label "com.wiredsquare.appliance.manifest=$label" \
    --label "org.opencontainers.image.version=$version" \
    --label "org.opencontainers.image.source=https://github.com/Wired-Square/opCA" \
    --output "type=docker,dest=$image"

[ -f "$keys/leaf.key" ] || "$archiver" keys "$keys"
"$archiver" pack "$keys" "$source" "$archive" "$image"
echo "image: $image"
echo "archive: $archive (source $source)"
