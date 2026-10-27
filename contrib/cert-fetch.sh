#!/usr/bin/env bash
#
# cert-fetch.sh - Install the server certificate opCA publishes for this host
#
# Usage: cert-fetch.sh CERT_URL CA_CERT CRL_URL KEY_PATH CERT_PATH [RELOAD_COMMAND]
#
# The certificate is only installed once it chains to CA_CERT, is not on the CA's CRL (itself
# verified), has not expired, matches the private key at KEY_PATH and expires later than the
# installed one; RELOAD_COMMAND then runs under sh. On any failure the installed file is kept.
# Exits non-zero (and posts to SLACK_WEBHOOK_URL, if set) on failure.
# See docs/cert-delivery.md.
#
set -euo pipefail

if [[ $# -lt 5 || $# -gt 6 ]]; then
  echo "Usage: $0 CERT_URL CA_CERT CRL_URL KEY_PATH CERT_PATH [RELOAD_COMMAND]" >&2
  exit 2
fi

cert_url=$1
ca_cert=$2
crl_url=$3
key_path=$4
cert_path=$5
reload=${6:-}

json_string() {
  local s=${1//\\/\\\\}
  s=${s//\"/\\\"}
  printf '"%s"' "${s//$'\n'/\\n}"
}

alert() {
  local msg
  msg="Cert fetch on $(hostname): $1"
  echo "$msg" >&2
  if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
    curl -fsS --max-time 20 -H 'Content-Type: application/json' \
      --data "{\"text\": $(json_string "$msg")}" "$SLACK_WEBHOOK_URL" >/dev/null ||
      echo "Slack notification failed" >&2
  fi
  exit 1
}

reject() {
  alert "$1. Kept $cert_path."
}

to_epoch() {
  date -u -d "$1" +%s 2>/dev/null || date -u -j -f '%b %e %T %Y %Z' "$1" +%s
}

not_after_epoch() {
  local not_after
  not_after=$(openssl x509 -in "$1" -noout -enddate) || return 1
  to_epoch "${not_after#notAfter=}"
}

tmp=$(mktemp "$cert_path.XXXXXX") || alert "cannot create a temporary file beside $cert_path"
trap 'rm -f "$tmp" "${crl:-}"' EXIT
crl=$(mktemp) || alert "cannot create a temporary file for the CRL"

err=$(curl -fsSL --max-time 60 -o "$tmp" "$cert_url" 2>&1) ||
  reject "downloading $cert_url failed: $err"
err=$(curl -fsSL --max-time 60 -o "$crl" "$crl_url" 2>&1) ||
  reject "downloading $crl_url failed: $err"

subject=$(openssl x509 -in "$ca_cert" -noout -subject) || alert "cannot read the CA certificate $ca_cert"
issuer=$(openssl crl -in "$crl" -noout -issuer 2>&1) ||
  reject "$crl_url is not a PEM CRL: $issuer"
[[ ${issuer#issuer=} == "${subject#subject=}" ]] ||
  reject "$crl_url was issued by '${issuer#issuer=}', not the CA"
# OpenSSL 1.1 exits 0 on "verify failure", so check the output too.
if ! verify=$(openssl crl -in "$crl" -noout -CAfile "$ca_cert" -verify 2>&1) || [[ $verify != *"verify OK"* ]]; then
  reject "$crl_url failed signature verification: $verify"
fi
next_update=$(openssl crl -in "$crl" -noout -nextupdate)
next_update=${next_update#nextUpdate=}
next_update_epoch=$(to_epoch "$next_update") || reject "$crl_url has no readable nextUpdate"
((next_update_epoch > $(date -u +%s))) || reject "$crl_url expired at $next_update"

openssl x509 -in "$tmp" -noout 2>/dev/null || reject "$cert_url is not a PEM certificate"
if ! verify=$(openssl verify -CAfile "$ca_cert" -crl_check -CRLfile "$crl" "$tmp" 2>&1) || [[ $verify != *": OK" ]]; then
  reject "$cert_url failed verification against the CA and its CRL: ${verify//$tmp/certificate}"
fi

key_pub=$(openssl pkey -in "$key_path" -pubout 2>&1) || alert "cannot read the private key $key_path: $key_pub"
[[ $(openssl x509 -in "$tmp" -noout -pubkey) == "$key_pub" ]] ||
  reject "$cert_url does not match the private key $key_path"

cmp -s "$tmp" "$cert_path" && exit 0

fetched_not_after=$(not_after_epoch "$tmp") || reject "$cert_url has no readable notAfter"
installed_not_after=$(not_after_epoch "$cert_path" 2>/dev/null) || installed_not_after=0
((fetched_not_after > installed_not_after)) ||
  reject "$cert_url expires no later than the installed certificate"

chmod 644 "$tmp"
mv -f "$tmp" "$cert_path" || reject "cannot move the new certificate into place"
echo "Installed a new certificate at $cert_path"

if [[ -n $reload ]]; then
  err=$(sh -c "$reload" 2>&1) ||
    alert "installed a new certificate at $cert_path, but '$reload' failed: $err"
fi
