#!/bin/bash
# Build netflowAgent on Linux (run on the target host, e.g. Ubuntu 18.04).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist/linux-x64"

echo "Building netflowAgent in $ROOT ..."
cd "$ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "Rust/cargo not found. Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

cargo build --release
mkdir -p "$DIST"
cp -f "$ROOT/target/release/netflowAgent" "$DIST/"
chmod +x "$DIST/netflowAgent"
cp -f "$ROOT/config.example.linux.toml" "$DIST/config.toml"
cp -f "$ROOT/scripts/install-linux.sh" "$ROOT/scripts/uninstall-linux.sh" "$ROOT/scripts/netflowAgent.service" "$DIST/"
chmod +x "$DIST/install-linux.sh" "$DIST/uninstall-linux.sh" "$DIST/build-linux.sh" 2>/dev/null || true
# Strip Windows CRLF if present (avoids: sudo: ./install-linux.sh: command not found)
for f in install-linux.sh uninstall-linux.sh build-linux.sh; do
    sed -i 's/\r$//' "$DIST/$f" 2>/dev/null || sed -i '' 's/\r$//' "$DIST/$f" 2>/dev/null || true
done

echo "Done: $DIST/netflowAgent"
file "$DIST/netflowAgent"
