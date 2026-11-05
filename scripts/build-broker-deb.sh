#!/bin/sh
# Builds opca-acme-broker and its .deb for one Linux platform in a throwaway
# container of that platform (emulated when it isn't the host's), from a
# vendored copy of the two crates. The binaries land in <work>/<arch>/bin and
# the .deb in <work>/<arch>/deb.
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
crate=$root/crates/opca-acme-broker
work=${OPCA_ACME_DOCKER_WORK:-$root/target/acme-docker}
out=$work/$arch

rm -rf "$work/src" "$out/deb" "$out/bin"
mkdir -p "$work/src/crates" "$work/src/.cargo" "$out/bin"
rsync -a --exclude target "$root/crates/opca-acme-api" "$crate" "$work/src/crates/"
sed -i.orig '/^\[dev-dependencies\]/,$d' "$work/src/crates/opca-acme-broker/Cargo.toml"
cp "$root/Cargo.lock" "$root/LICENSE" "$work/src/"
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -1)
cat > "$work/src/Cargo.toml" <<TOML
[workspace]
members = ["crates/opca-acme-api", "crates/opca-acme-broker"]
resolver = "3"

[workspace.package]
version = "$version"
edition = "2024"
rust-version = "1.99"
TOML
cp "$root/.cargo/config.toml" "$work/src/.cargo/config.toml"
(cd "$work/src" && cargo vendor --versioned-dirs vendor >> .cargo/config.toml)

docker run --rm --platform "$platform" --name "opca-deb-$arch-$$" -v "$work:/work" \
    -w /work/src -e "CARGO_TARGET_DIR=/work/$arch/target" -e "ARCH=$arch" \
    rust:1.99-bookworm sh -ec '
        cargo build --offline --release -p opca-acme-broker
        [ -x "/work/$ARCH/tools/bin/cargo-deb" ] ||
            (cd / && cargo install cargo-deb --version 3.8.0 --locked --root "/work/$ARCH/tools")
        CARGO_NET_OFFLINE=true "/work/$ARCH/tools/bin/cargo-deb" -p opca-acme-broker \
            --no-build --output "/work/$ARCH/deb/"'
cp "$out/target/release/opca-acme-broker" "$out/target/release/opca-acme" "$out/bin/"
