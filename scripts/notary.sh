#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$SCRIPT_DIR/../.env.local"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE — copy from .env.local.example and fill in your values" >&2
  exit 1
fi

# shellcheck source=/dev/null
source "$ENV_FILE"

APPLE_ID=$(op read --account "$OP_ACCOUNT" "$APPLE_ID_REF")
APPLE_TEAM_ID=$(op read --account "$OP_ACCOUNT" "$APPLE_TEAM_ID_REF")
APPLE_NOTARY_PASSWORD=$(op read --account "$OP_ACCOUNT" "$APPLE_NOTARY_PASSWORD_REF")

NOTARY_ARGS=(--apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_NOTARY_PASSWORD")

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
