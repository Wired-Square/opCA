#!/usr/bin/env bash
# build-acme-app.sh's signing, on a stand-in image tarball with throwaway keys
# and a stand-in op: wired-square signs only with a code-signing leaf of its
# root, and its index verifies against that root.
#
# usage: tests/app-signing.sh (APPLIANCEOS as for build-acme-app.sh)
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
build=$repo/scripts/build-acme-app.sh
appliance=${APPLIANCEOS:-$repo/../ApplianceOS}
# shellcheck source=SCRIPTDIR/../../../../ApplianceOS/scripts/app-index.sh
. "$appliance/scripts/app-index.sh"
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
failures=0
check() {
    local name=$1
    shift
    if "$@"; then echo "ok - $name"; else echo "not ok - $name" >&2; failures=$((failures + 1)); fi
}

blob() {
    local digest
    digest=$(shasum -a 256 "$1" | cut -d' ' -f1)
    mv "$1" "$t/image/blobs/sha256/$digest"
    echo "sha256:$digest"
}
mkdir -p "$t/image/blobs/sha256"
jq -n '{config: {Labels: {
    "com.wiredsquare.appliance.manifest": ({name: "opca-acme", version: "0.0.1"} | tojson),
    "org.opencontainers.image.version": "0.0.1"}}}' >"$t/config"
jq -n --arg config "$(blob "$t/config")" '{config: {digest: $config}}' >"$t/manifest"
jq -n --arg manifest "$(blob "$t/manifest")" '{manifests: [{digest: $manifest,
    platform: {architecture: "arm64"},
    annotations: {"io.containerd.image.name": "ghcr.io/wired-square/opca-acme:0.0.1"}}]}' >"$t/image/index.json"
tar -cf "$t/opca-acme.tar" -C "$t/image" index.json blobs

"$appliance/scripts/make-app-archive.sh" keys "$t/shipped" >/dev/null
"$appliance/scripts/make-app-archive.sh" keys "$t/other" >/dev/null
shipped_leaf() {
    local dir=$t/$1 extensions=$2
    mkdir "$dir"
    "$openssl" ecparam -name prime256v1 -genkey -noout -out "$dir/leaf.key"
    "$openssl" req -new -key "$dir/leaf.key" -subj "/CN=Not a code signer" -out "$dir/leaf.csr"
    "$openssl" x509 -req -in "$dir/leaf.csr" -CA "$t/shipped/root.pem" -CAkey "$t/shipped/root.key" \
        -CAcreateserial -days 1 -extfile <(echo "$extensions") -out "$dir/leaf.pem" 2>/dev/null
}
shipped_leaf server-auth "extendedKeyUsage=serverAuth"
shipped_leaf no-eku "basicConstraints=CA:FALSE"

mkdir "$t/bin"
cat >"$t/bin/op" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$t/op.log"
case \$* in
    "read --account wiredsquare.1password.com op://Software Development/WiredSquare-Codesigning/certificate") cat "$t/shipped/leaf.pem" ;;
    "read --account wiredsquare.1password.com op://Software Development/WiredSquare-Codesigning/private_key") cat "$t/shipped/leaf.key" ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$t/bin/op"

signs() { WIRED_SQUARE_ROOT=$t/shipped/root.pem PATH=$t/bin:$PATH "$build" --image "$t/opca-acme.tar" "$@"; }
verifies() {
    local archive=$1 source=$2 root=$3
    rm -rf "$t/out" && mkdir "$t/out" && tar -xf "$archive" -C "$t/out"
    "$openssl" cms -verify -binary -inform DER -in "$t/out/index.json.sig" -content "$t/out/index.json" \
        -CAfile "$root" -purpose codesign -out /dev/null 2>/dev/null &&
        jq -e --arg source "$source" '.source == $source and .apps[0].manifest.name == "opca-acme"' \
            "$t/out/index.json" >/dev/null
}
archive=$t/opca-acme-wired-square.tar

signs_with_op() {
    signs --source wired-square >/dev/null && verifies "$archive" wired-square "$t/shipped/root.pem" &&
        ! verifies "$archive" wired-square "$t/other/root.pem" && (($(wc -l <"$t/op.log") == 2))
}
check "wired-square signs with the leaf op reads, and verifies against its root alone" signs_with_op
rm -f "$archive"

signs_with_keys() {
    signs --source wired-square --keys "$t/shipped" >/dev/null && verifies "$archive" wired-square "$t/shipped/root.pem"
}
check "wired-square signs with --keys chaining to its root" signs_with_keys
rm -f "$archive"

refuses() {
    ! signs --source wired-square --keys "$t/$1" 2>"$t/err" >/dev/null &&
        grep -q "not a code-signing leaf" "$t/err" && [[ ! -e $archive ]]
}
for leaf in other server-auth no-eku; do
    check "wired-square refuses the $leaf leaf" refuses "$leaf"
done

signs_as_test() {
    signs --keys "$t/other" >/dev/null && verifies "$t/opca-acme-opca-test.tar" opca-test "$t/other/root.pem"
}
check "opca-test signs with any --keys, unchecked" signs_as_test

((failures == 0))
