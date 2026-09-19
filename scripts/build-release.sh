#!/usr/bin/env bash

# Exit immediately on error
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$PROJECT_DIR/dist"

echo "=========================================="
echo " Building VirusTotal Smart Inspector Release "
echo "=========================================="

NAME=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$PROJECT_DIR/manifest.json')).name.toLowerCase().replace(/\s+/g, '-'))")
VERSION=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$PROJECT_DIR/manifest.json')).version)")
ZIP_NAME="${NAME}-v${VERSION}.zip"
ZIP_PATH="$DIST_DIR/$ZIP_NAME"

echo "Extension Version: v$VERSION"
echo "Output Archive:    $ZIP_PATH"

# Prepare dist directory
mkdir -p "$DIST_DIR"
rm -f "$ZIP_PATH"

# Validate Syntax
echo "--> Validating JavaScript and JSON syntax..."
node -e "JSON.parse(require('fs').readFileSync('$PROJECT_DIR/manifest.json'))"
node -c "$PROJECT_DIR"/src/background/*.js "$PROJECT_DIR"/src/content/*.js "$PROJECT_DIR"/src/popup/*.js "$PROJECT_DIR"/src/options/*.js

# Create Zip package excluding git, dist, tests, and scratch files
echo "--> Packaging release archive..."
cd "$PROJECT_DIR"
zip -r "$ZIP_PATH" manifest.json README.md LICENSE icons/ src/ -x "*.DS_Store" "*__pycache__*"

echo "------------------------------------------"
echo "SUCCESS! Release package built successfully."
echo "Archive File: $ZIP_PATH"
echo "File Size:    $(du -h "$ZIP_PATH" | cut -f1)"
echo "SHA256:       $(sha256sum "$ZIP_PATH" | cut -d' ' -f1)"
echo "=========================================="
