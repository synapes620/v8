#!/usr/bin/env bash
# Run the ValueDeserializer OOB PoC
# Usage: bash value_serializer_oob_run.sh [d8_path]
set -e
D8="${1:-/tmp/d8_build_mca/d8}"
SCRIPT_DIR="$(cd "$(dirname "$0")"; pwd)"
echo "[*] d8: $D8"
echo "[*] JS:  $SCRIPT_DIR/value_serializer_oob.js"
echo "[*] GDB: $SCRIPT_DIR/value_serializer_oob.gdb"
echo ""
gdb -batch \
    -ex "set pagination off" \
    -x "$SCRIPT_DIR/value_serializer_oob.gdb" \
    "$D8" 2>&1
