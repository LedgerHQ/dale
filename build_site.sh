#!/bin/bash
# Build the site directory for local testing or CI deployment
# Usage: ./build_site.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SITE_DIR="$SCRIPT_DIR/site"

# Copy source and requirements into site/
rm -rf "$SITE_DIR/dale"
cp -r "$SCRIPT_DIR/src/dale" "$SITE_DIR/dale"
cp "$SCRIPT_DIR/requirements.txt" "$SITE_DIR/requirements.txt"

# Generate file list manifest
cd "$SITE_DIR"
find dale -name "*.py" | sort > manifest.txt

echo "Site built in $SITE_DIR"
