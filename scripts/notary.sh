#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
# .env may be a 1Password-mounted FIFO: test with -e, and read it once.
# Values are literal, not shell: the signing identity has spaces and brackets.
if [[ -e .env ]]; then
  while IFS='=' read -r key value; do
    [[ $key =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && export "$key=$value"
  done < .env
fi

NOTARY_ARGS=(
  --apple-id "${APPLE_ID:?set in .env}"
  --team-id "${APPLE_TEAM_ID:?set in .env}"
  --password "${APPLE_PASSWORD:?set in .env}"
)

case "${1:-}" in
  history)
    xcrun notarytool history "${NOTARY_ARGS[@]}"
    ;;
  log)
    if [[ -z "${2:-}" ]]; then
      echo "Usage: notary.sh log <submission-id>" >&2
      exit 1
    fi
    xcrun notarytool log "$2" "${NOTARY_ARGS[@]}"
    ;;
  *)
    echo "Usage: notary.sh {history|log <submission-id>}" >&2
    exit 1
    ;;
esac
