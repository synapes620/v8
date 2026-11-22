// Bug: module-compiler.cc:1501-1507 — polymorphic feedback array parity OOB
//
// Root cause:
//   SBXCHECK_LE(checked_polymorphic_length,
//               FeedbackConstants::kSlotsPerInstruction * kMaxPolymorphism)
//   i.e. SBXCHECK_LE(len, 2 * 4 = 8)
//
//   The check bounds the max length but NOT its parity.
//   The loop increments j by kSlotsPerInstruction (2) and reads get(j+1).
//   For an odd length L, the last iteration has j = L-1, reads get(L) — OOB.
//
//     L=1: j=0 → get(0) OK, get(1) OOB   (1 past end)
//     L=3: j=0,2 → get(2) OK, get(3) OOB (1 past end)
//     L=7: j=0,2,4,6 → get(6) OK, get(7) OOB
//
//   The OOB slot is used as `int count = Smi::ToInt(polymorphic->get(j+1))`.
//   It reads adjacent heap memory — typically the next object's map pointer
//   or length — and interprets it as a Smi-encoded integer count.
//
//   For the call_ref branch, the even slot j is also cast:
//     Tagged<WasmFuncRef> target = Cast<WasmFuncRef>(polymorphic->get(j))
//   If the FixedArray's actual allocation was 0 elements but its length field
//   was corrupted to 1, get(0) itself is OOB and Cast<WasmFuncRef> on the
//   adjacent map/heap word is a type confusion.
//
// Triggering:
//   Under normal execution kSlotsPerInstruction=2 entries are added at a time,
//   so length is always even {0,2,4,6,8}. An odd length requires in-sandbox
//   corruption of the FixedArray's raw length Smi field.
//   SBXCHECK_LE allows any value ≤ 8 without aborting, including odd ones.
//
// Sandbox boundary note:
//   This is SBXCHECK-guarded code — a sandbox bypass primitive.
//   In-sandbox heap corruption of a polymorphic FixedArray's length to an odd
//   value triggers OOB reads during TurboFan tier-up feedback processing.
//   The type confusion (Cast<WasmFuncRef> on arbitrary heap data) is then
//   used by AddCallRefCandidate which calls funcref->internal(isolate_),
//   dereferencing the confused pointer — a controlled out-of-sandbox read.
//
// Step 1: Build a Wasm module with polymorphic call_ref.
//   - Use at least 2 different function references to build a poly feedback entry
//   - The feedback FixedArray grows to length 2 (one pair of slots)
//
// Step 2: In-sandbox corruption.
//   - Corrupt the FixedArray length field (a Smi at offset kTaggedSize from base)
//     from 2 to 1 (or from 4 to 3, etc.)
//   - This requires a separate in-sandbox write primitive (ArrayBuffer OOB,
//     corrupted JSTypedArray length, etc.)
//
// Step 3: Trigger tier-up.
//   - Call the function enough times that V8 schedules a TurboFan compilation
//   - EnterOptimizedCodeScope → CollectFeedback → processes the corrupted array
//   - SBXCHECK_LE(1, 8) passes; loop reads get(1) OOB
//
// Demo below: shows the feedback array structure and that parity is never checked.

'use strict';

// Wasm bytes for:
//   (module
//     (type $fty (func (result i32)))
//     (table 2 funcref)
//     (func $f1 (result i32) i32.const 11)
//     (func $f2 (result i32) i32.const 22)
//     (func $callref (param i32) (result i32)
//       local.get 0
//       table.get 0
//       call_ref $fty)
//     (elem (i32.const 0) $f1 $f2)
//     (export "callref" (func $callref))
//   )
// Wasm module with call_indirect — same feedback code path (L1511-1517)
// (module
//   (type 0: () -> i32)        (type 1: (i32) -> i32)
//   (table funcref 2)
//   (func f0: i32.const 11)    (func f1: i32.const 22)
//   (func callindirect (param i32)(result i32):
//     local.get 0, call_indirect type=0 table=0)
//   (elem (i32.const 0) funcref [f0, f1])
//   (export "callindirect" (func 2))
// )
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

(async () => {
  let mod, inst;
  try {
    mod  = await WebAssembly.compile(wasmBytes);
    inst = await WebAssembly.instantiate(mod);
  } catch (e) {
    print('Wasm compile/instantiate failed (adjust bytes for exact V8 encoding): ' + e);
    print('');
    print('=== Bug summary: wasm-js.cc:1501-1507 ===');
    print('SBXCHECK_LE bounds length to <=8 but no parity check.');
    print('Odd length L causes get(L) OOB on last iteration (j = L-1, reads j+1 = L).');
    print('Fix: add   SBXCHECK_EQ(0, checked_polymorphic_length % kSlotsPerInstruction)');
    return;
  }

  const { callindirect } = inst.exports;
  print('callindirect(0) = ' + callindirect(0));  // 11
  print('callindirect(1) = ' + callindirect(1));  // 22

  // Drive polymorphic feedback: alternate between two call targets
  for (let i = 0; i < 20000; i++) callindirect(i & 1);
  print('Feedback seeded with two call_indirect targets (expected array length = 4).');
  print('');
  print('=== Parity check missing at module-compiler.cc:1501 ===');
  print('SBXCHECK_LE(len, 8) passes for len in {1,3,5,7} — no SBXCHECK for even-ness.');
  print('In-sandbox: corrupt FixedArray length from 4 to 3.');
  print('  → loop: j=0 (get[0],get[1] OK), j=2 (get[2] OK, get[3] OOB)');
  print('  → Smi::ToInt(heap_word_past_array) used as polymorphic call count');
  print('  → if array had 0 elements and length set to 1:');
  print('       Cast<WasmFuncRef>(get[0]) reads adjacent map/heap word → type confusion');
  print('       AddCallRefCandidate → funcref->internal(isolate_) on confused pointer');
  print('');
  print('Fix: after SBXCHECK_LE add:');
  print('  SBXCHECK_EQ(0, checked_polymorphic_length %');
  print('                     FeedbackConstants::kSlotsPerInstruction);');
})();
