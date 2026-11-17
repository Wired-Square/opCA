#!/usr/bin/env bash
# Builds the opca-acme ApplianceOS app image for one platform as a docker-load
# tarball, then packs it with a signed index into an archive the console's
# Apps › Install takes. --image packs a tarball built before instead.
#
# As source wired-square, which every image ships, it signs with the
# WiredSquare-Codesigning leaf from 1Password, its key piped to the signer and
# never written out, or with the PEM in WIRED_SQUARE_SIGNING_CERT and
# WIRED_SQUARE_SIGNING_KEY when set (CI), once the leaf is a code-signing leaf
# of the Wired Square Apps root, whose PEM is in WIRED_SQUARE_APPS_ROOT. With
# --keys, any source signs with <dir>'s leaf.pem and leaf.key, made there when
# it holds none. Without either, a test source (opca-test by default) signs
# with OPCA_TEST_SIGNING_CERT and OPCA_TEST_SIGNING_KEY from .env (base64 of
# leaf.pem and leaf.key), so a box's source keeps verifying across builds.
#
# usage: scripts/build-acme-app.sh [--keys <dir>] [--platform linux/arm64|linux/amd64] [--source <name>] [--image <image.tar>]
#
# Signing and an arm64 build's erratum check need wslib-appliance-xtask 0.2.8
# or later, and the page needs npm and the Wired Square mirror. Output lands
# in target/acme-app, or beside --image.
set -euo pipefail
usage="usage: $0 [--keys <dir>] [--platform linux/arm64|linux/amd64] [--source <name>] [--image <image.tar>]"
platform=linux/arm64
source=opca-test
keys=
image=
while (($# >= 2)); do
    case $1 in
        --keys) keys=$2 ;;
        --platform) platform=$2 ;;
        --source) source=$2 ;;
        --image) image=$2 ;;
        *) echo "$usage" >&2; exit 2 ;;
    esac
    shift 2
done
(($# == 0)) || { echo "$usage" >&2; exit 2; }
case $platform in
    linux/arm64 | linux/amd64) arch=${platform#linux/} ;;
    *) echo "$usage" >&2; exit 2 ;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
codesigning="op://Software Development/WiredSquare-Codesigning"
if [[ $keys ]]; then
    [[ -f $keys/leaf.key ]] || wslib-appliance-xtask app-archive keys "$keys"
    cp "$keys/leaf.pem" "$work/signer.pem"
    signing_key() { cat "$keys/leaf.key"; }
elif [[ $source == wired-square && -n ${WIRED_SQUARE_SIGNING_KEY:-} ]]; then
    printf '%s\n' "${WIRED_SQUARE_SIGNING_CERT:?WIRED_SQUARE_SIGNING_KEY needs WIRED_SQUARE_SIGNING_CERT}" >"$work/signer.pem"
    signing_key() { printf '%s\n' "$WIRED_SQUARE_SIGNING_KEY"; }
elif [[ $source == wired-square ]]; then
    op read --account wiredsquare.1password.com "$codesigning/certificate" >"$work/signer.pem"
    signing_key() { op read --account wiredsquare.1password.com "$codesigning/private_key"; }
else
    # .env may be a 1Password-mounted FIFO: test with -e, and read it once.
    if [[ -e $root/.env ]]; then
        while IFS='=' read -r key value; do
            case $key in
                OPCA_TEST_SIGNING_CERT | OPCA_TEST_SIGNING_KEY) export "$key=$value" ;;
            esac
        done <"$root/.env"
    fi
    : "${OPCA_TEST_SIGNING_CERT:?no --keys, and not set in .env}"
    : "${OPCA_TEST_SIGNING_KEY:?no --keys, and not set in .env}"
    printf %s "$OPCA_TEST_SIGNING_CERT" | base64 -d >"$work/signer.pem"
    signing_key() { printf %s "$OPCA_TEST_SIGNING_KEY" | base64 -d; }
fi
[[ $source != wired-square ]] || wslib-appliance-xtask app-archive verify "$work/signer.pem"

if [[ -z $image ]]; then
    out=$root/target/acme-app
    version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -1)
    image=$out/opca-acme-$version-$arch.tar

    label=$(cargo run -q -p opca-acme-broker --example appliance-label -- "$arch")
    (cd "$root/crates/opca-acme-broker/ui" && npm ci --no-audit --no-fund && npm run build)
    "$root/scripts/stage-broker-src.sh" "$out"

    builder="appliance-image"
    docker buildx inspect "$builder" >/dev/null 2>&1 ||
        docker buildx create --name "$builder" --driver docker-container >/dev/null
    build() {
        docker buildx build --builder "$builder" --platform "$platform" \
            --file "$root/crates/opca-acme-broker/appliance/Dockerfile" "$@" "$out/src"
    }
    if [[ $arch == arm64 ]]; then
        build --target binary --output "type=local,dest=$out/$arch"
        wslib-appliance-xtask erratum-843419 "$out/$arch/opca-acme-broker"
    fi
    build \
        --tag "ghcr.io/wired-square/opca-acme:$version" \
        --label "com.wiredsquare.appliance.manifest=$label" \
        --label "org.opencontainers.image.version=$version" \
        --label "org.opencontainers.image.source=https://github.com/Wired-Square/opCA" \
        --output "type=docker,dest=$image"
    echo "image: $image"
fi

signing_key | wslib-appliance-xtask app-archive pack --source "$source" --cert "$work/signer.pem" --key - \
    "${image%.tar}-$source.tar" "$image"
