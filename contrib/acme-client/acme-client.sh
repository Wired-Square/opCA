#!/bin/sh
#
# acme-client.sh - Keep a certificate from an RFC 8555 server, such as the opCA broker, with lego
#
# Configured only by the environment (see .env.example). Orders a certificate when there is none
# under ACME_DATA, then renews it every ACME_CHECK_INTERVAL seconds once it is within
# ACME_RENEW_DAYS of expiry. ACME_HOOK runs under sh after each issue or renewal, with ACME_CERT
# and ACME_KEY set. ACME_ONCE=1 makes one pass and exits with its status. See README.md.
#
set -eu

log() {
  echo "acme-client: $*" >&2
}

die() {
  log "$*"
  exit 2
}

whole_number() {
  case $2 in
    '' | *[!0-9]*) die "$1 must be a whole number, not '$2'" ;;
  esac
}

for name in ACME_SERVER ACME_EMAIL ACME_DOMAINS ACME_CHALLENGE ACME_CA_BUNDLE; do
  eval "value=\${$name:-}"
  [ -n "$value" ] || die "$name is required; see .env.example"
done
if [ ! -f "$ACME_CA_BUNDLE" ] || [ ! -r "$ACME_CA_BUNDLE" ]; then
  die "ACME_CA_BUNDLE $ACME_CA_BUNDLE is not a readable file"
fi

renew_days=${ACME_RENEW_DAYS:-10}
interval=${ACME_CHECK_INTERVAL:-43200}
retry=${ACME_RETRY_INTERVAL:-3600}
whole_number ACME_RENEW_DAYS "$renew_days"
whole_number ACME_CHECK_INTERVAL "$interval"
whole_number ACME_RETRY_INTERVAL "$retry"
data=${ACME_DATA:-/data}

set -f
set -- --server "$ACME_SERVER" --email "$ACME_EMAIL" --accept-tos --path "$data" \
  --key-type "${ACME_KEY_TYPE:-ec256}"
first=
IFS=', '
for domain in $ACME_DOMAINS; do
  set -- "$@" --domains "$domain"
  first=${first:-$domain}
done
unset IFS
[ -n "$first" ] || die "ACME_DOMAINS names no domain"

case $ACME_CHALLENGE in
  http) set -- "$@" --http ;;
  tls) set -- "$@" --tls ;;
  dns:?*) set -- "$@" --dns "${ACME_CHALLENGE#dns:}" ;;
  *) die "ACME_CHALLENGE must be http, tls or dns:<lego provider>, not '$ACME_CHALLENGE'" ;;
esac
# shellcheck disable=SC2086 # ACME_ARGS is a list of lego options, split on spaces.
set -- "$@" ${ACME_ARGS:-}

# lego names the files after the first domain, with a wildcard's * as _.
case $first in
  '*.'*) first=_${first#\*} ;;
esac
export LEGO_CA_CERTIFICATES="$ACME_CA_BUNDLE"
export ACME_CERT="$data/certificates/$first.crt" ACME_KEY="$data/certificates/$first.key"

child=
trap 'kill "$child" 2>/dev/null; exit 143' TERM INT

# In the background, so a signal is handled at once rather than once the child exits.
spawn() {
  "$@" &
  child=$!
  wait "$child"
}

fingerprint() {
  if [ -f "$ACME_CERT" ]; then cksum <"$ACME_CERT"; fi
}

pass() {
  before=$(fingerprint)
  if [ -n "$before" ]; then
    spawn lego "$@" renew --days "$renew_days" || return
  else
    log "no certificate at $ACME_CERT, ordering one from $ACME_SERVER"
    spawn lego "$@" run || return
  fi
  [ "$(fingerprint)" != "$before" ] || return 0
  log "new certificate at $ACME_CERT"
  if [ -n "${ACME_HOOK:-}" ] && ! spawn sh -c "$ACME_HOOK"; then
    log "ACME_HOOK failed: $ACME_HOOK"
    return 1
  fi
}

if [ "${ACME_ONCE:-}" = 1 ]; then
  pass "$@"
  exit
fi
while :; do
  if pass "$@"; then
    pause=$interval
  else
    pause=$retry
    log "failed, trying again in $retry s"
  fi
  spawn sleep "$pause"
done
