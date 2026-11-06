#!/usr/bin/env bash
# Builds the opca-acme ApplianceOS app image for one platform as a docker-load
# tarball, then packs it with a signed index into an archive the console's
# Apps › Install takes. --image packs a tarball built before instead.
#
# As source wired-square, which every image ships, it signs with the
# WiredSquare-Codesigning leaf from 1Password, its key piped to openssl and
# never written out, once the leaf is a code-signing leaf of the root
# ApplianceOS ships (WIRED_SQUARE_ROOT overrides it). With --keys, any source
# signs with <dir>'s leaf.pem and leaf.key, made there by make-app-archive.sh
# when it holds none. Without either, a test source (opca-test by default)
# signs with OPCA_TEST_SIGNING_CERT and OPCA_TEST_SIGNING_KEY from .env (base64
# of leaf.pem and leaf.key), so a box's source keeps verifying across builds.
#
# usage: scripts/build-acme-app.sh [--keys <dir>] [--platform linux/arm64|linux/amd64] [--source <name>] [--image <image.tar>]
#
# APPLIANCEOS names an ApplianceOS checkout (default: ../ApplianceOS beside
# this repository). An arm64 build needs wslib-appliance-xtask for its
# erratum check, and the page needs npm and the Wired Square mirror. Output
# lands in target/acme-app, or beside --image.
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
appliance=${APPLIANCEOS:-$root/../ApplianceOS}
archiver=$appliance/scripts/make-app-archive.sh
[[ -x $archiver ]] || { echo "no $archiver; set APPLIANCEOS" >&2; exit 1; }
# shellcheck source=SCRIPTDIR/../../ApplianceOS/scripts/app-index.sh
. "$appliance/scripts/app-index.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/images"
codesigning="op://Software Development/WiredSquare-Codesigning"
if [[ $keys ]]; then
    [[ -f $keys/leaf.key ]] || "$archiver" keys "$keys"
    cp "$keys/leaf.pem" "$work/signer.pem"
    signing_key() { cat "$keys/leaf.key"; }
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
if [[ $source == wired-square ]]; then
    shipped=${WIRED_SQUARE_ROOT:-$appliance/layers/meta-applianceos/recipes-apps/applianceos-app-sources/files/wired-square.pem}
    "$openssl" verify -CAfile "$shipped" -untrusted "$work/signer.pem" -purpose codesign "$work/signer.pem" >/dev/null ||
        { echo "the signer is not a code-signing leaf of $shipped" >&2; exit 1; }
fi

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

archive=${image%.tar}-$source.tar
entry "$image" >"$work/entries"
digest=$(jq -r '.manifest.image.digest' "$work/entries")
cp "$image" "$work/images/${digest/:/-}.tar"
signing_key | sign "$source" "$work" "$work/signer.pem" /dev/stdin
archive "$archive" "$work" "$source"
