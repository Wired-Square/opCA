#!/bin/sh
# Builds the broker for Linux in a throwaway container, takes step-ca out of
# its image, and runs the Docker test against both.
set -eu
crate=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$crate/../.." && pwd)
work=${OPCA_ACME_DOCKER_WORK:-$root/target/acme-docker}

rm -rf "$work/src"
mkdir -p "$work/src/crates" "$work/src/.cargo" "$work/bin"
rsync -a --exclude target "$root/crates/opca-acme-api" "$crate" "$work/src/crates/"
sed -i.orig '/^\[dev-dependencies\]/,$d' "$work/src/crates/opca-acme-broker/Cargo.toml"
cp "$root/Cargo.lock" "$work/src/"
cat > "$work/src/Cargo.toml" <<TOML
[workspace]
members = ["crates/opca-acme-api", "crates/opca-acme-broker"]
resolver = "3"

[workspace.package]
version = "0.0.0"
edition = "2024"
rust-version = "1.99"
TOML
cp "$root/.cargo/config.toml" "$work/src/.cargo/config.toml"
(cd "$work/src" && cargo vendor --versioned-dirs vendor >> .cargo/config.toml)

docker run --rm --name "opca-e-build-$$" -v "$work/src:/src" -w /src \
    -e CARGO_TARGET_DIR=/src/target rust:1.99-bookworm \
    cargo build --offline -p opca-acme-broker
cp "$work/src/target/debug/opca-acme-broker" "$work/bin/"

docker create --name "opca-e-extract-$$" smallstep/step-ca:0.28.1 > /dev/null
docker cp "opca-e-extract-$$:/usr/local/bin/step-ca" "$work/bin/step-ca"
docker rm "opca-e-extract-$$" > /dev/null

OPCA_ACME_DOCKER_TEST=1 OPCA_ACME_DOCKER_BIN="$work/bin" \
    cargo test -p opca-acme-broker --test step_ca_docker
