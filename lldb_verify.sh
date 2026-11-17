#!/bin/bash
# lldb_verify.sh — automated LLDB session to confirm H < SB_BASE
# Usage: bash lldb_verify.sh

D8=/tmp/d8_build_mca/d8
JS=/home/user/v8/heap_escape_lldb.js

echo "[*] Launching d8 under LLDB..."

lldb --batch \
  --one-line "process launch --stop-at-entry" \
  --one-line-on-crash "bt" \
  -o "run" \
  -o "process handle SIGTRAP -s false -p true -n true" \
  -o "continue" \
  -o "process status" \
  -o "memory find -e 0x01ECFE00 -s 4 -- 0x0 0x7fffffffffff" \
  -o "memory find -e 0xFEECFEEC -s 4 -- 0x0 0x7fffffffffff" \
  -o "continue" \
  -- "$D8" --sandbox-testing --allow-natives-syntax "$JS" 2>&1

echo "[*] Done."
