#!/bin/sh
# Builds the broker and its .deb for Linux in a throwaway container, takes
# step-ca out of its image, and runs the Docker tests against them.
set -eu
crate=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$crate/../.." && pwd)
work=${OPCA_ACME_DOCKER_WORK:-$root/target/acme-docker}

rm -rf "$work/src"
mkdir -p "$work/src/crates" "$work/src/.cargo" "$work/bin"
rm -rf "$work/deb"
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

docker run --rm --name "opca-e-build-$$" -v "$work:/work" -w /work/src \
    -e CARGO_TARGET_DIR=/work/target rust:1.99-bookworm sh -ec '
        cargo build --offline --release -p opca-acme-broker
        [ -x /work/tools/bin/cargo-deb ] ||
            (cd / && cargo install cargo-deb --version 3.8.0 --locked --root /work/tools)
        CARGO_NET_OFFLINE=true /work/tools/bin/cargo-deb -p opca-acme-broker --no-build \
            --output /work/deb/'
cp "$work/target/release/opca-acme-broker" "$work/target/release/opca-acme" "$work/bin/"

docker create --name "opca-e-extract-$$" smallstep/step-ca:0.28.1 > /dev/null
docker cp "opca-e-extract-$$:/usr/local/bin/step-ca" "$work/bin/step-ca"
docker rm "opca-e-extract-$$" > /dev/null

OPCA_ACME_DOCKER_TEST=1 OPCA_ACME_DOCKER_BIN="$work/bin" OPCA_ACME_DOCKER_DEB="$work/deb" \
    cargo test -p opca-acme-broker --test step_ca_docker
