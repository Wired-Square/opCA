#!/bin/sh
# Stages a workspace of the broker's two crates, without their dev-dependencies
# and with every dependency vendored, at <work>/src, for a build that can't
# reach the registries.
#
# usage: scripts/stage-broker-src.sh <work>
set -eu
[ $# = 1 ] || { echo "usage: $0 <work>" >&2; exit 2; }
work=$1
root=$(cd "$(dirname "$0")/.." && pwd)

rm -rf "$work/src"
mkdir -p "$work/src/crates" "$work/src/.cargo"
rsync -a --exclude target "$root/crates/opca-acme-api" "$root/crates/opca-acme-broker" "$work/src/crates/"
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
# A Cortex-A53 (the Pi 3, the Zero 2 W) can miscompute an address at an
# unpatched erratum 843419 site. bookworm's ld leaves one even with its fix on;
# lld's fix patches it, so an arm64 build needs lld.
cat >> "$work/src/.cargo/config.toml" <<'TOML'

[target.aarch64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-fuse-ld=lld", "-C", "link-arg=-Wl,--fix-cortex-a53-843419"]
TOML
