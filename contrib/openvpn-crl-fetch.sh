#!/usr/bin/env bash
#
# openvpn-crl-fetch.sh - Install the CA's published CRL as OpenVPN's crl-verify file
#
# Usage: openvpn-crl-fetch.sh CRL_URL CA_CERT CRL_PATH
#
# The CRL is only installed once its signature, issuer and nextUpdate check out; on any
# failure the installed file is kept. Exits non-zero (and posts to SLACK_WEBHOOK_URL, if
# set) on failure or when the installed CRL expires within CRL_WARN_DAYS (default 3).
# See docs/crl-batches.md.
#
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 CRL_URL CA_CERT CRL_PATH" >&2
  exit 2
fi

crl_url=$1
ca_cert=$2
crl_path=$3
warn_days=${CRL_WARN_DAYS:-3}

json_string() {
  local s=${1//\\/\\\\}
  s=${s//\"/\\\"}
  printf '"%s"' "${s//$'\n'/\\n}"
}

alert() {
  local msg
  msg="CRL fetch on $(hostname): $1"
  echo "$msg" >&2
  if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
    curl -fsS --max-time 20 -H 'Content-Type: application/json' \
      --data "{\"text\": $(json_string "$msg")}" "$SLACK_WEBHOOK_URL" >/dev/null ||
      echo "Slack notification failed" >&2
  fi
  exit 1
}

reject() {
  alert "$1. Kept $crl_path."
}

next_update_epoch() {
  local next_update
  next_update=$(openssl crl -in "$1" -noout -nextupdate) || return 1
  next_update=${next_update#nextUpdate=}
  date -u -d "$next_update" +%s 2>/dev/null || date -u -j -f '%b %e %T %Y %Z' "$next_update" +%s
}

tmp=$(mktemp "$crl_path.XXXXXX") || alert "cannot create a temporary file beside $crl_path"
trap 'rm -f "$tmp"' EXIT

err=$(curl -fsSL --max-time 60 -o "$tmp" "$crl_url" 2>&1) ||
  reject "downloading $crl_url failed: $err"

issuer=$(openssl crl -in "$tmp" -noout -issuer 2>&1) ||
  reject "$crl_url is not a PEM CRL: $issuer"
subject=$(openssl x509 -in "$ca_cert" -noout -subject) || alert "cannot read the CA certificate $ca_cert"
[[ ${issuer#issuer=} == "${subject#subject=}" ]] ||
  reject "$crl_url was issued by '${issuer#issuer=}', not the CA"

# OpenSSL 1.1 exits 0 on "verify failure", so check the output too.
if ! verify=$(openssl crl -in "$tmp" -noout -CAfile "$ca_cert" -verify 2>&1) || [[ $verify != *"verify OK"* ]]; then
  reject "$crl_url failed signature verification: $verify"
fi

now=$(date -u +%s)
fetched_next_update=$(next_update_epoch "$tmp") ||
  reject "$crl_url has no readable nextUpdate"
((fetched_next_update > now)) ||
  reject "$crl_url expired at $(openssl crl -in "$tmp" -noout -nextupdate)"

if ! cmp -s "$tmp" "$crl_path"; then
  # OpenVPN re-reads crl-verify after dropping privileges.
  chmod 644 "$tmp"
  mv -f "$tmp" "$crl_path" || reject "cannot move the new CRL into place"
  echo "Installed a new CRL at $crl_path"
fi

remaining=$(($(next_update_epoch "$crl_path") - now))
((remaining > warn_days * 86400)) ||
  alert "the installed CRL at $crl_path expires in $((remaining / 3600)) hours; every OpenVPN client is rejected once it does. Is the CA's CRL release running?"
