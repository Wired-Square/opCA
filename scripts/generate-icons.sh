#!/usr/bin/env bash
#
# Generate app icons for macOS (.icns), Windows (.ico), and Linux (PNGs)
# from the master logo SVG.
#
# Requirements:
#   rsvg-convert (librsvg) and magick (ImageMagick 7+)
#
#   macOS:   brew install librsvg imagemagick
#   Ubuntu:  apt-get install librsvg2-bin imagemagick icnsutils
#
# On macOS, iconutil is used for .icns (built-in).
# On Linux, png2icns (from icnsutils) is used instead.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MASTER_SVG="$REPO_ROOT/frontend/public/logo.svg"
ICON_DIR="$REPO_ROOT/crates/opca-tauri/icons"

if [[ ! -f "$MASTER_SVG" ]]; then
  echo "Error: master SVG not found at $MASTER_SVG" >&2
  exit 1
fi

for cmd in rsvg-convert magick; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: $cmd is required but not found" >&2
    exit 1
  fi
done

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Rendering PNGs from $MASTER_SVG..."

# Render all required sizes
SIZES=(16 24 32 48 64 128 256 512 1024)
for size in "${SIZES[@]}"; do
  rsvg-convert -w "$size" -h "$size" "$MASTER_SVG" -o "$TMPDIR/${size}.png"
done
echo "  Rendered ${#SIZES[@]} sizes."

# --- Tauri PNGs ---
cp "$TMPDIR/32.png"  "$ICON_DIR/32x32.png"
cp "$TMPDIR/128.png" "$ICON_DIR/128x128.png"
cp "$TMPDIR/256.png" "$ICON_DIR/128x128@2x.png"
echo "Tauri PNGs updated."

# --- Windows .ico (16, 24, 32, 48, 64, 128, 256) ---
magick "$TMPDIR/16.png" "$TMPDIR/24.png" "$TMPDIR/32.png" \
       "$TMPDIR/48.png" "$TMPDIR/64.png" "$TMPDIR/128.png" \
       "$TMPDIR/256.png" "$ICON_DIR/icon.ico"
echo "Windows icon.ico created."

# --- macOS .icns ---
if command -v iconutil &>/dev/null; then
  # macOS: use iconutil with an .iconset directory
  ICONSET="$TMPDIR/icon.iconset"
  mkdir -p "$ICONSET"

  cp "$TMPDIR/16.png"   "$ICONSET/icon_16x16.png"
  cp "$TMPDIR/32.png"   "$ICONSET/icon_16x16@2x.png"
  cp "$TMPDIR/32.png"   "$ICONSET/icon_32x32.png"
  cp "$TMPDIR/64.png"   "$ICONSET/icon_32x32@2x.png"
  cp "$TMPDIR/128.png"  "$ICONSET/icon_128x128.png"
  cp "$TMPDIR/256.png"  "$ICONSET/icon_128x128@2x.png"
  cp "$TMPDIR/256.png"  "$ICONSET/icon_256x256.png"
  cp "$TMPDIR/512.png"  "$ICONSET/icon_256x256@2x.png"
  cp "$TMPDIR/512.png"  "$ICONSET/icon_512x512.png"
  cp "$TMPDIR/1024.png" "$ICONSET/icon_512x512@2x.png"

  iconutil -c icns "$ICONSET" -o "$ICON_DIR/icon.icns"
  echo "macOS icon.icns created (iconutil)."
elif command -v png2icns &>/dev/null; then
  # Linux: use png2icns from icnsutils
  # png2icns supports 16, 32, 48, 128, 256, 512, 1024
  png2icns "$ICON_DIR/icon.icns" \
    "$TMPDIR/16.png" "$TMPDIR/32.png" "$TMPDIR/48.png" \
    "$TMPDIR/128.png" "$TMPDIR/256.png" "$TMPDIR/512.png" \
    "$TMPDIR/1024.png"
  echo "macOS icon.icns created (png2icns)."
else
  echo "Warning: neither iconutil nor png2icns found — skipping .icns" >&2
fi

echo "Done. Icons written to $ICON_DIR/"
ls -la "$ICON_DIR/"
